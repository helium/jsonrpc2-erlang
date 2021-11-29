%% Copyright 2021 Helium Systems Inc
%% Copyright 2013-2014 Viktor Söderqvist
%%
%% Licensed under the Apache License, Version 2.0 (the "License");
%% you may not use this file except in compliance with the License.
%% You may obtain a copy of the License at
%%
%%     http://www.apache.org/licenses/LICENSE-2.0
%%
%% Unless required by applicable law or agreed to in writing, software
%% distributed under the License is distributed on an "AS IS" BASIS,
%% WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
%% See the License for the specific language governing permissions and
%% limitations under the License.

%% @doc This module handles JSON-RPC 2.0 requests.
%%
%% JSON encoding and decoding is not handled by this module. Thus, it must be
%% handled outside, by the caller.
%%
%% The format of the parsed JSON is expected to be an Erlang map, but the
%% older EEP18 format is also valid for drop-in backward compatibility.
-module(jsonrpc2).

-export([handle/2, handle/3, handle/4, handle/5, parseerror/0]).

-type json() :: true | false | null | binary() | [json()] | {[{binary(), json()}]} | map().
-type method() :: binary().
-type params() :: [json()] | {[{binary(), json()}]} | map().
-type id() :: number() | binary() | null.
-type errortype() ::
    parse_error
    | method_not_found
    | invalid_params
    | internal_error
    | invalid_request
    | server_error.
-type error() ::
    errortype()
    | {errortype(), json()}
    | {jsonrpc2, integer(), binary()}
    | {jsonrpc2, integer(), binary(), json()}.
-type request() :: {method(), params(), id() | undefined} | invalid_request.
-type response() :: noreply | {reply, json()}.

-type handlerfun() :: fun((method(), params()) -> json()).
% should be the same as lists:map/2
-type mapfun() :: fun((fun((A) -> B), [A]) -> [B]).

-export_type([
    json/0,
    method/0,
    params/0,
    id/0,
    handlerfun/0,
    mapfun/0,
    response/0,
    errortype/0,
    error/0
]).

%% @doc Handles a raw JSON-RPC request, using the supplied JSON decode and
%% encode functions.
-spec handle(Req :: term(), handlerfun(), JsonDecode :: fun(), JsonEncode :: fun()) ->
    noreply | {reply, term()}.
handle(Req, HandlerFun, JsonDecode, JsonEncode) when
    is_function(HandlerFun, 2),
    is_function(JsonDecode, 1),
    is_function(JsonEncode, 1)
->
    handle(Req, HandlerFun, fun lists:map/2, JsonDecode, JsonEncode).

%% @doc Handles a raw JSON-RPC request, using the supplied JSON decode and
%% encode functions and a custom map function.
-spec handle(
    Req :: term(),
    handlerfun(),
    mapfun(),
    JsonDecode :: fun(),
    JsonEncode :: fun()
) -> noreply | {reply, term()}.
handle(Req, HandlerFun, MapFun, JsonDecode, JsonEncode) when
    is_function(HandlerFun, 2),
    is_function(MapFun, 2),
    is_function(JsonDecode, 1),
    is_function(JsonEncode, 1)
->
    Response =
        try JsonDecode(Req) of
            DecodedJson -> handle(DecodedJson, HandlerFun, MapFun)
        catch
            _:_ -> {reply, parseerror()}
        end,
    case Response of
        noreply ->
            noreply;
        {reply, Reply} ->
            try JsonEncode(Reply) of
                EncodedReply -> {reply, EncodedReply}
            catch
                _C:_E:Stack ->
                    error_logger:error_msg(
                        "Failed encoding reply as JSON: ~p~n~p",
                        [Reply, Stack]
                    ),
                    {reply, Error} = make_standard_error_response(internal_error, null),
                    {reply, JsonEncode(Error)}
            end
    end.

%% @doc Handles the requests using the handler function. Batch requests are
%% handled sequentially. Since this module doesn't handle the JSON encoding and
%% decoding, the request must be JSON decoded before passing it to this
%% function. Likewise, if a reply is returned, it should be JSON encoded before
%% sending it to the client.
-spec handle(json(), handlerfun()) -> response().
handle(Req, HandlerFun) ->
    handle(Req, HandlerFun, fun lists:map/2).

%% @doc Handles the requests using the handler function and a custom map
%% function for batch requests. The map function should be compatible with
%% lists:map/2. This is useful for concurrent processing of batch requests.
-spec handle(json(), handlerfun(), mapfun()) -> response().
handle(Req, HandlerFun, MapFun) ->
    case parse(Req) of
        BatchRpc when is_list(BatchRpc), length(BatchRpc) > 0 ->
            Responses = MapFun(fun(Rpc) -> dispatch(Rpc, HandlerFun) end, BatchRpc),
            merge_responses(Responses);
        Rpc ->
            dispatch(Rpc, HandlerFun)
    end.

%% @doc Returns a jsonrpc2 parse error response.
%%
%% This function can be used to manually create a JSON-SPC error response, for
%% the case when the client sends invalid JSON. This function is exported for
%% completeness, since the JSON encoding and decoding is not handled by this
%% module.
-spec parseerror() -> json().
parseerror() ->
    make_error(-32700, <<"Parse error.">>, null).

%% helpers

-spec make_result_response(json(), id() | undefined) -> response().
make_result_response(_Result, undefined) ->
    noreply;
make_result_response(Result, Id) ->
    {reply, #{
        <<"jsonrpc">> => <<"2.0">>,
        <<"result">> => Result,
        <<"id">> => Id
    }}.

-spec make_standard_error_response(errortype(), id() | undefined) -> response().
make_standard_error_response(ErrorType, Id) ->
    {Code, Msg} = error_code_and_message(ErrorType),
    make_error_response(Code, Msg, Id).

-spec make_standard_error_response(errortype(), json(), id() | undefined) -> response().
make_standard_error_response(ErrorType, Data, Id) ->
    {Code, Msg} = error_code_and_message(ErrorType),
    make_error_response(Code, Msg, Data, Id).

%% @doc Custom error, with data
-spec make_error_response(integer(), binary(), json(), id() | undefined) -> response().
make_error_response(_Code, _Message, _Data, undefined) ->
    noreply;
make_error_response(Code, Message, Data, Id) ->
    {reply, make_error(Code, Message, Data, Id)}.

%% @doc Custom error, without data
-spec make_error_response(integer(), binary(), id() | undefined) -> response().
make_error_response(_Code, _Message, undefined) ->
    noreply;
make_error_response(Code, Message, Id) ->
    {reply, make_error(Code, Message, Id)}.

%% @doc Make json-rpc error response, with data
-spec make_error(integer(), binary(), json() | undefined, id()) -> json().
make_error(Code, Msg, Data, Id) ->
    #{
        <<"jsonrpc">> => <<"2.0">>,
        <<"error">> => #{
            <<"code">> => Code,
            <<"message">> => Msg,
            <<"data">> => Data
        },
        <<"id">> => Id
    }.

%% @doc Make json-rpc error response, without data
-spec make_error(integer(), binary(), id()) -> json().
make_error(Code, Msg, Id) ->
    R = #{<<"error">> := Error} = make_error(Code, Msg, undefined, Id),
    R#{<<"error">> => maps:remove(<<"data">>, Error)}.

%% @doc Parses the RPC part of an already JSON decoded request. Returns a tuple
%% {Method, Params, Id} for a single request, 'invalid_request' for an invalid
%% request and a list of these for a batch request. An Id value of 'undefined'
%% is used when the id is not present in the request.
-spec parse(json()) -> request() | [request()].
parse(Reqs) when is_list(Reqs) ->
    [parse(Req) || Req <- Reqs];
parse(
    #{
        <<"jsonrpc">> := <<"2.0">>,
        <<"method">> := Method
    } = Req
) when is_binary(Method) ->
    Id = maps:get(<<"id">>, Req, undefined),
    case
        Id == undefined orelse Id == null orelse
            is_binary(Id) orelse is_number(Id)
    of
        false ->
            invalid_request;
        true ->
            Params = maps:get(<<"params">>, Req, []),
            case is_map(Params) andalso map_size(Params) == 0 of
                true ->
                    %% arguably this ought to be an empty map but
                    %% using an empty list here makes pattern matching
                    %% in handlers easier since one must use `map_size/1'
                    %% in a guard clause to determine if a map given in
                    %% a function head is actually empty.
                    %%
                    %% Matching on an empty list has no such ambiguity,
                    %% and we've already decided the parameter map is
                    %% empty, so why do that again inside the handler?
                    {Method, [], Id};
                false ->
                    {Method, Params, Id}
            end
    end;
parse({Req}) ->
    Version = proplists:get_value(<<"jsonrpc">>, Req),
    Method = proplists:get_value(<<"method">>, Req),
    Params = proplists:get_value(<<"params">>, Req, []),
    Id = proplists:get_value(<<"id">>, Req, undefined),
    case
        Version =:= <<"2.0">> andalso
            is_binary(Method) andalso
            (is_list(Params) orelse is_tuple(Params)) andalso
            (Id =:= undefined orelse Id =:= null orelse
                is_binary(Id) orelse
                is_number(Id))
    of
        true ->
            {Method, Params, Id};
        false ->
            invalid_request
    end;
parse(_) ->
    invalid_request.

%% @doc Calls the handler function, catches errors and composes a json-rpc response.
-spec dispatch(request(), handlerfun()) -> response().
dispatch({Method, Params, Id}, HandlerFun) ->
    try HandlerFun(Method, Params) of
        Response -> make_result_response(Response, Id)
    catch
        throw:E when
            E == method_not_found;
            E == invalid_params;
            E == internal_error;
            E == server_error
        ->
            make_standard_error_response(E, Id);
        throw:{E, Data} when
            E == method_not_found;
            E == invalid_params;
            E == internal_error;
            E == server_error
        ->
            make_standard_error_response(E, Data, Id);
        throw:{jsonrpc2, Code, Message} when is_integer(Code), is_binary(Message) ->
            %% Custom error, without data
            %% -32000 to -32099	Server error Reserved for implementation-defined server-errors.
            %% The remainder of the space is available for application defined errors.
            make_error_response(Code, Message, Id);
        throw:{jsonrpc2, Code, Message, Data} when is_integer(Code), is_binary(Message) ->
            %% Custom error, with data
            make_error_response(Code, Message, Data, Id);
        Class:Error:Stack ->
            error_logger:error_msg(
                "Error in JSON-RPC handler for method ~s with params ~p (id: ~p): ~p:~p from ~p",
                [Method, Params, Id, Class, Error, Stack]
            ),
            make_standard_error_response(internal_error, Id)
    end;
dispatch(_, _HandlerFun) ->
    make_standard_error_response(invalid_request, null).

%% @doc Returns JSON-RPC error code and error message
error_code_and_message(invalid_request) -> {-32600, <<"Invalid Request.">>};
error_code_and_message(method_not_found) -> {-32601, <<"Method not found.">>};
error_code_and_message(invalid_params) -> {-32602, <<"Invalid params.">>};
error_code_and_message(internal_error) -> {-32603, <<"Internal error.">>};
error_code_and_message(server_error) -> {-32000, <<"Server error.">>}.

%% @doc Transforms a list of responses into a single response.
-spec merge_responses([response()]) -> response().
merge_responses(Responses) when is_list(Responses) ->
    case [Reply || {reply, Reply} <- Responses] of
        [] -> noreply;
        Replies -> {reply, Replies}
    end.

-ifdef(TEST).
-include_lib("eunit/include/eunit.hrl").

%% Testing the examples from http://www.jsonrpc.org/specification

test_handler(<<"subtract">>, [42, 23]) -> 19;
test_handler(<<"subtract">>, [23, 42]) -> -19;
test_handler(<<"subtract">>, #{<<"subtrahend">> := 23, <<"minuend">> := 42}) -> 19;
test_handler(<<"subtract">>, {[{<<"subtrahend">>, 23}, {<<"minuend">>, 42}]}) -> 19;
test_handler(<<"subtract">>, {[{<<"minuend">>, 42}, {<<"subtrahend">>, 23}]}) -> 19;
test_handler(<<"update">>, [1, 2, 3, 4, 5]) -> ok;
test_handler(<<"sum">>, [1, 2, 4]) -> 7;
test_handler(<<"get_data">>, []) -> [<<"hello">>, 5];
test_handler(_, _) -> throw(method_not_found).

%% rpc call with positional parameters
eep18_call_test() ->
    Req =
        {[
            {<<"jsonrpc">>, <<"2.0">>},
            {<<"method">>, <<"subtract">>},
            {<<"params">>, [42, 23]},
            {<<"id">>, 1}
        ]},
    {reply, #{
        <<"jsonrpc">> := <<"2.0">>,
        <<"result">> := 19,
        <<"id">> := 1
    }} = handle(Req, fun test_handler/2).

map_call_test() ->
    Req = #{
        <<"jsonrpc">> => <<"2.0">>,
        <<"method">> => <<"subtract">>,
        <<"params">> => [42, 23],
        <<"id">> => 1
    },
    {reply, #{
        <<"jsonrpc">> := <<"2.0">>,
        <<"result">> := 19,
        <<"id">> := 1
    }} = handle(Req, fun test_handler/2).

%% rpc call with positional parameters, reverse order
eep18_call2_test() ->
    Req =
        {[
            {<<"jsonrpc">>, <<"2.0">>},
            {<<"method">>, <<"subtract">>},
            {<<"params">>, [23, 42]},
            {<<"id">>, 2}
        ]},
    {reply, #{
        <<"jsonrpc">> := <<"2.0">>,
        <<"result">> := -19,
        <<"id">> := 2
    }} = handle(Req, fun test_handler/2).

map_call2_test() ->
    Req = #{
        <<"jsonrpc">> => <<"2.0">>,
        <<"method">> => <<"subtract">>,
        <<"params">> => [23, 42],
        <<"id">> => 2
    },
    {reply, #{
        <<"jsonrpc">> := <<"2.0">>,
        <<"result">> := -19,
        <<"id">> := 2
    }} = handle(Req, fun test_handler/2).

%% rpc call with named parameters
eep18_named_test() ->
    Req =
        {[
            {<<"jsonrpc">>, <<"2.0">>},
            {<<"method">>, <<"subtract">>},
            {<<"params">>, {[{<<"subtrahend">>, 23}, {<<"minuend">>, 42}]}},
            {<<"id">>, 3}
        ]},
    {reply, #{
        <<"jsonrpc">> := <<"2.0">>,
        <<"result">> := 19,
        <<"id">> := 3
    }} = handle(Req, fun test_handler/2).

map_named_test() ->
    Req = #{
        <<"jsonrpc">> => <<"2.0">>,
        <<"method">> => <<"subtract">>,
        <<"params">> => #{
            <<"subtrahend">> => 23,
            <<"minuend">> => 42
        },
        <<"id">> => 3
    },
    {reply, #{
        <<"jsonrpc">> := <<"2.0">>,
        <<"result">> := 19,
        <<"id">> := 3
    }} = handle(Req, fun test_handler/2).

%% rpc call with named parameters, reverse order
eep18_named2_test() ->
    Req =
        {[
            {<<"jsonrpc">>, <<"2.0">>},
            {<<"method">>, <<"subtract">>},
            {<<"params">>, {[{<<"minuend">>, 42}, {<<"subtrahend">>, 23}]}},
            {<<"id">>, 4}
        ]},
    {reply, #{
        <<"jsonrpc">> := <<"2.0">>,
        <<"result">> := 19,
        <<"id">> := 4
    }} = handle(Req, fun test_handler/2).

map_named2_test() ->
    Req = #{
        <<"jsonrpc">> => <<"2.0">>,
        <<"method">> => <<"subtract">>,
        <<"params">> => #{
            <<"minuend">> => 42,
            <<"subtrahend">> => 23
        },
        <<"id">> => 4
    },
    {reply, #{
        <<"jsonrpc">> := <<"2.0">>,
        <<"result">> := 19,
        <<"id">> := 4
    }} = handle(Req, fun test_handler/2).

%% a Notification
eep18_notif_test() ->
    Req =
        {[
            {<<"jsonrpc">>, <<"2.0">>},
            {<<"method">>, <<"update">>},
            {<<"params">>, [1, 2, 3, 4, 5]}
        ]},
    noreply = handle(Req, fun test_handler/2).

map_notif_test() ->
    Req = #{
        <<"jsonrpc">> => <<"2.0">>,
        <<"method">> => <<"update">>,
        <<"params">> => [1, 2, 3, 4, 5]
    },
    noreply = handle(Req, fun test_handler/2).

%% a Notification + non-existent method
eep18_notif2_test() ->
    Req = {[{<<"jsonrpc">>, <<"2.0">>}, {<<"method">>, <<"foobar">>}]},
    noreply = handle(Req, fun test_handler/2).

map_notif2_test() ->
    Req = #{
        <<"jsonrpc">> => <<"2.0">>,
        <<"method">> => <<"foobar">>
    },
    noreply = handle(Req, fun test_handler/2).

%% rpc call of non-existent method
eep18_bad_method_test() ->
    Req = {[{<<"jsonrpc">>, <<"2.0">>}, {<<"method">>, <<"foobar">>}, {<<"id">>, <<"1">>}]},
    {reply, #{
        <<"jsonrpc">> := <<"2.0">>,
        <<"error">> := #{
            <<"code">> := -32601,
            <<"message">> := <<"Method not found.">>
        },
        <<"id">> := <<"1">>
    }} = handle(Req, fun test_handler/2).

map_bad_method_test() ->
    Req = #{
        <<"jsonrpc">> => <<"2.0">>,
        <<"method">> => <<"foobar">>,
        <<"id">> => <<"1">>
    },
    {reply, #{
        <<"jsonrpc">> := <<"2.0">>,
        <<"error">> := #{
            <<"code">> := -32601,
            <<"message">> := <<"Method not found.">>
        },
        <<"id">> := <<"1">>
    }} = handle(Req, fun test_handler/2).

%% rpc call with invalid JSON
%% Not applicable, since JSON parsing is not done in this module. We test the error
%% response though.
bad_json_test() ->
    #{
        <<"jsonrpc">> := <<"2.0">>,
        <<"error">> := #{
            <<"code">> := -32700,
            <<"message">> := <<"Parse error.">>
        },
        <<"id">> := null
    } = parseerror().

%% rpc call with invalid Request object
eep18_bad_rpc_test() ->
    Req = {[{<<"jsonrpc">>, <<"2.0">>}, {<<"method">>, 1}, {<<"params">>, <<"bar">>}]},
    {reply, #{
        <<"jsonrpc">> := <<"2.0">>,
        <<"error">> := #{
            <<"code">> := -32600,
            <<"message">> := <<"Invalid Request.">>
        },
        <<"id">> := null
    }} = handle(Req, fun test_handler/2).

map_bad_rpc_test() ->
    Req = #{
        <<"jsonrpc">> => <<"2.0">>,
        <<"method">> => 1,
        <<"params">> => <<"bar">>
    },
    {reply, #{
        <<"jsonrpc">> := <<"2.0">>,
        <<"error">> := #{
            <<"code">> := -32600,
            <<"message">> := <<"Invalid Request.">>
        },
        <<"id">> := null
    }} = handle(Req, fun test_handler/2).

%% rpc call Batch, invalid JSON:
%% Not applicable, see bad_json_test/0 above.
bad_json_batch_test() ->
    ok.

%% rpc call with an empty Array
empty_batch_test() ->
    Req = [],
    {reply, #{
        <<"jsonrpc">> := <<"2.0">>,
        <<"error">> := #{
            <<"code">> := -32600,
            <<"message">> := <<"Invalid Request.">>
        },
        <<"id">> := null
    }} = handle(Req, fun test_handler/2).

%% rpc call with an invalid Batch (but not empty)
invalid_batch_test() ->
    Req = [1],
    {reply, [
        #{
            <<"jsonrpc">> := <<"2.0">>,
            <<"error">> := #{
                <<"code">> := -32600,
                <<"message">> := <<"Invalid Request.">>
            },
            <<"id">> := null
        }
    ]} = handle(Req, fun test_handler/2).

%% rpc call with invalid Batch
invalid_batch2_test() ->
    Req = [1, 2, 3],
    Expected = fun
        (
            #{
                <<"jsonrpc">> := <<"2.0">>,
                <<"error">> := #{
                    <<"code">> := -32600,
                    <<"message">> := <<"Invalid Request.">>
                },
                <<"id">> := null
            }
        ) ->
            true;
        (_) ->
            false
    end,
    {reply, Reply} = handle(Req, fun test_handler/2),
    ?assert(lists:all(Expected, Reply)).

%% rpc call Batch
eep18_batch_test() ->
    Req = [
        {[
            {<<"jsonrpc">>, <<"2.0">>},
            {<<"method">>, <<"sum">>},
            {<<"params">>, [1, 2, 4]},
            {<<"id">>, <<"1">>}
        ]},
        {[
            {<<"jsonrpc">>, <<"2.0">>},
            {<<"method">>, <<"notify_hello">>},
            {<<"params">>, [7]}
        ]},
        {[
            {<<"jsonrpc">>, <<"2.0">>},
            {<<"method">>, <<"subtract">>},
            {<<"params">>, [42, 23]},
            {<<"id">>, <<"2">>}
        ]},
        {[{<<"foo">>, <<"boo">>}]},
        {[
            {<<"jsonrpc">>, <<"2.0">>},
            {<<"method">>, <<"foo.get">>},
            {<<"params">>, {[{<<"name">>, <<"myself">>}]}},
            {<<"id">>, <<"5">>}
        ]},
        {[
            {<<"jsonrpc">>, <<"2.0">>},
            {<<"method">>, <<"get_data">>},
            {<<"id">>, <<"9">>}
        ]}
    ],
    {reply, [
        #{<<"jsonrpc">> := <<"2.0">>, <<"result">> := 7, <<"id">> := <<"1">>},
        #{<<"jsonrpc">> := <<"2.0">>, <<"result">> := 19, <<"id">> := <<"2">>},
        #{
            <<"jsonrpc">> := <<"2.0">>,
            <<"error">> := #{
                <<"code">> := -32600,
                <<"message">> := <<"Invalid Request.">>
            },
            <<"id">> := null
        },
        #{
            <<"jsonrpc">> := <<"2.0">>,
            <<"error">> := #{
                <<"code">> := -32601,
                <<"message">> := <<"Method not found.">>
            },
            <<"id">> := <<"5">>
        },
        #{<<"jsonrpc">> := <<"2.0">>, <<"result">> := [<<"hello">>, 5], <<"id">> := <<"9">>}
    ]} =
        handle(Req, fun test_handler/2).

map_batch_test() ->
    Req = [
        #{
            <<"jsonrpc">> => <<"2.0">>,
            <<"method">> => <<"sum">>,
            <<"params">> => [1, 2, 4],
            <<"id">> => <<"1">>
        },
        #{
            <<"jsonrpc">> => <<"2.0">>,
            <<"method">> => <<"notify_hello">>,
            <<"params">> => [7]
        },
        #{
            <<"jsonrpc">> => <<"2.0">>,
            <<"method">> => <<"subtract">>,
            <<"params">> => [42, 23],
            <<"id">> => <<"2">>
        },
        #{<<"foo">> => <<"bar">>},
        #{
            <<"jsonrpc">> => <<"2.0">>,
            <<"method">> => <<"foo.get">>,
            <<"params">> => #{<<"name">> => <<"myself">>},
            <<"id">> => <<"5">>
        },
        #{
            <<"jsonrpc">> => <<"2.0">>,
            <<"method">> => <<"get_data">>,
            <<"id">> => <<"9">>
        }
    ],
    {reply, [
        #{<<"jsonrpc">> := <<"2.0">>, <<"result">> := 7, <<"id">> := <<"1">>},
        #{<<"jsonrpc">> := <<"2.0">>, <<"result">> := 19, <<"id">> := <<"2">>},
        #{
            <<"jsonrpc">> := <<"2.0">>,
            <<"error">> := #{
                <<"code">> := -32600,
                <<"message">> := <<"Invalid Request.">>
            },
            <<"id">> := null
        },
        #{
            <<"jsonrpc">> := <<"2.0">>,
            <<"error">> := #{
                <<"code">> := -32601,
                <<"message">> := <<"Method not found.">>
            },
            <<"id">> := <<"5">>
        },
        #{<<"jsonrpc">> := <<"2.0">>, <<"result">> := [<<"hello">>, 5], <<"id">> := <<"9">>}
    ]} =
        handle(Req, fun test_handler/2).

%% rpc call Batch (all notifications)
eep18_batch_notif_test() ->
    Req = [
        {[
            {<<"jsonrpc">>, <<"2.0">>},
            {<<"method">>, <<"notify_sum">>},
            {<<"params">>, [1, 2, 4]}
        ]},
        {[
            {<<"jsonrpc">>, <<"2.0">>},
            {<<"method">>, <<"notify_hello">>},
            {<<"params">>, [7]}
        ]}
    ],
    noreply = handle(Req, fun test_handler/2).

map_batch_notif_test() ->
    Req = [
        #{<<"jsonrpc">> => <<"2.0">>, <<"method">> => <<"notify_sum">>, <<"params">> => [1, 2, 4]},
        #{<<"jsonrpc">> => <<"2.0">>, <<"method">> => <<"notify_hello">>, <<"params">> => [7]}
    ],
    noreply = handle(Req, fun test_handler/2).

-define(ENCODED_REQUEST, <<
    "{\"jsonrpc\":\"2.0\","
    "\"method\":\"subtract\","
    "\"params\":[42,23],"
    "\"id\":1}"
>>).
-define(EEP18_DECODED_REQUEST,
    {[
        {<<"jsonrpc">>, <<"2.0">>},
        {<<"method">>, <<"subtract">>},
        {<<"params">>, [42, 23]},
        {<<"id">>, 1}
    ]}
).
-define(MAP_DECODED_REQUEST, #{
    <<"jsonrpc">> => <<"2.0">>,
    <<"method">> => <<"subtract">>,
    <<"params">> => [42, 23],
    <<"id">> => 1
}).
-define(ENCODED_RESPONSE, <<
    "{\"jsonrpc\":\"2.0\","
    "\"result\":19,"
    "\"id\":1}"
>>).
-define(DECODED_RESPONSE, #{
    <<"jsonrpc">> := <<"2.0">>,
    <<"result">> := 19,
    <<"id">> := 1
}).
-define(ENCODED_PARSE_ERROR, <<
    "{\"jsonrpc\":\"2.0\","
    "\"error\":{\"code\":-32700,"
    "\"message\":\"Parse error.\"},"
    "\"id\":null}"
>>).
-define(DECODED_PARSE_ERROR, #{
    <<"jsonrpc">> := <<"2.0">>,
    <<"error">> := #{
        <<"code">> := -32700,
        <<"message">> := <<"Parse error.">>
    },
    <<"id">> := null
}).

%% define json encode and decode only for the cases we need in the tests
eep18_json_decode(?ENCODED_REQUEST) -> ?EEP18_DECODED_REQUEST.
map_json_decode(?ENCODED_REQUEST) -> ?MAP_DECODED_REQUEST.
json_encode(?DECODED_RESPONSE) -> ?ENCODED_RESPONSE;
json_encode(?DECODED_PARSE_ERROR) -> ?ENCODED_PARSE_ERROR.

%% test handle/4 with encode and decode callbacks
eep18_json_callbacks_test() ->
    Req = ?ENCODED_REQUEST,
    Reply = ?ENCODED_RESPONSE,
    {reply, Reply} = handle(
        Req,
        fun test_handler/2,
        fun eep18_json_decode/1,
        fun json_encode/1
    ).

map_json_callbacks_test() ->
    Req = ?ENCODED_REQUEST,
    Reply = ?ENCODED_RESPONSE,
    {reply, Reply} = handle(
        Req,
        fun test_handler/2,
        fun map_json_decode/1,
        fun json_encode/1
    ).

eep18_parse_error_test() ->
    Error = ?ENCODED_PARSE_ERROR,
    {reply, Error} = handle(
        <<"dummy">>,
        fun test_handler/2,
        fun eep18_json_decode/1,
        fun json_encode/1
    ).

map_parse_error_test() ->
    Error = ?ENCODED_PARSE_ERROR,
    {reply, Error} = handle(
        <<"dummy">>,
        fun test_handler/2,
        fun map_json_decode/1,
        fun json_encode/1
    ).

-endif.

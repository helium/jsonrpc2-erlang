JSON-RPC 2.0 for Erlang
=======================

Transport agnostic library for JSON-RPC 2.0 servers and clients.

This is a fork of the [upstream](https://github.com/zuiderkwast/jsonrpc2-erlang) library. 

It was forked to modernize the underlying assumptions about JSON for Erlang,
especially the now pervasive use of maps to represent JSON data as the internal
Erlang data structure.

(In the bad old days before maps were introduced in OTP 17, there were several different
mostly compatible proplist-ish ways of representing JSON data internally in Erlang -
the so-called [EEP18](https://www.erlang.org/eeps/eep-0018.html) format. Thankfully 
the introduction of maps has mostly eliminated these representations.)

Features
--------

* EEP18 format still supported for drop-in replacement in existing code
* can use any JSON encoder and decoder that supports maps as the internal
  Erlang data structure format,
* transport neutral
* dispatches parsed requests to a simple callback function
* supports an optional callback "map" function for batch requests, e.g. to
  support concurrent processing of the requests in a batch,
* handles rpc calls and notifications,
* supports named and unnamed parameters,
* includes unit tests for all examples in the JSON-RPC 2.0 specification.

Example
-------

``` erlang
1> Json = <<"{\"jsonrpc\": \"2.0\", \"method\": \"foo\", \"params\": [1,2,3], \"id\": 1}">>.
<<"{\"jsonroc\": \"2.0\", \"method\": \"foo\", \"params\": [1,2,3], \"id\": 1}">>
2>
2> MyHandler = fun (<<"foo">>, Params) -> lists:reverse(Params);
2>                 (_, _) -> throw(method_not_found)
2>             end.
#Fun<erl_eval.12.82930912>
3>
3> jsonrpc2:handle(Json, MyHandler, fun jiffy:decode/1, fun jiffy:encode/1).
{reply,<<"{\"jsonrpc\":\"2.0\",\"result\":[3,2,1],\"id\":1}">>}
4>
4> jsonrpc2:handle(<<"dummy">>, MyHandler, fun jiffy:decode/1, fun jiffy:encode/1).
{reply,<<"{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32700,\"message\":\"Parse error.\"},\"id\":null}">>}
5>
5> jsonrpc2:handle(<<"{\"x\":42}">>, MyHandler, fun jiffy:decode/1, fun jiffy:encode/1).
{reply,<<"{\"jsonrpc\":\"2.0\",\"error\":{\"code\":-32600,\"message\":\"Invalid Request.\"},\"id\":null}">>}
```

Types
-----

```Erlang
json() :: true | false | null | binary() | [json()] | {[{binary(), json()}]} | map().

handlerfun() :: fun((method(), params()) -> json()).
method() :: binary().
params() :: [json()] | {[{binary(), json()}]}.

mapfun() :: fun((fun((A) -> B), [A]) -> [B]). %% the same as lists:map/2
```

Functions
---------

Any of the `jsonrpc2:handle/2,3,4,5` functions can be used to handle JSON-RPC
request by delegating the actual procedure call to a handler callback function.
They all return `{reply, Data}` where Data is a result or an error response or
`noreply` when no response should be sent to the client. The handler callback
function must return a term that can be encoded to JSON using the
representation explained on the page https://github.com/davisp/jiffy#data-format,
as required by jiffy and other compatible JSON parses.

```Erlang
handle(json(), handlerfun()) -> {reply, json()} | noreply
```

Handles decoded JSON and returns a reply as decoded JSON or noreply. Use
this if you want to handle JSON encoding separately.

```Erlang
handle(json(), handlerfun(), mapfun()) -> {reply, json()} | noreply
```

Like `handle/2`, handles decoded JSON, but takes an extra
"map" function callback to be used instead of `lists:map/2`
for batch processing. The map function should be a function that behaves
similarly to `lists:map/2`, such as the `plists:map/2`
from the plists library for concurrent batch handling.

```Erlang
handle(Req::term(), handlerfun(), JsonDecode::fun(), JsonEncode::fun()) ->
    {reply, term()} | noreply
```

Handles JSON as binary or string. Uses the supplied functions
JsonDecode to parse the JSON request and JsonEncode to encode the reply as JSON.

```Erlang
handle(Req::term(), handlerfun(), mapfun(), JsonDecode::fun(),
    JsonEncode::fun()) -> {reply, term()} | noreply
```

Like `handle/4`, but also takes a map function for batch
processing. See `handle/3` above.

Error Handling
--------------

A requests that is not valid JSON results in a "Parse error" JSON-RPC response.

An invalid JSON-RPC request (though valid JSON) results in an "Invalid Request"
response. In these two cases the handler callback function is never called.

To produce an error response from the handler function, you may throw one of
the exceptions below. They will be caught and turned into a corresponding
JSON-RPC error response.

  * `throw(method_not_found)` is reported as "Method not found" (-32601)
  * `throw(invalid_params)` is reported as "Invalid params" (-32602)
  * `throw(internal_error)` is reported as "Internal error" (-32603)
  * `throw(server_error)` is reported as "Server error" (-32000)

If you also want to include `data` in the JSON-RPC error response, throw a pair
with the error type and the data, such as `{internal_error, Data}`.

For your own *application-defined errors*, it is possible to set a custom error
code by throwing a tuple with the atom `jsonrpc2`, an integer error code, a
binary message and optional data.

  * `throw({jsonrpc2, Code, Message)`
  * `throw({jsonrpc2, Code, Message, Data})`

If any other exception is thrown or an error occurs in the handler, this is
caught, an error message is logged (using the standard error logger
`error_logger:error_msg/2`) and an "Internal error" response is returned.

If you're working with already parsed JSON, i.e. you're using `handle/2` or
`handle/3`, you may want to produce an error message that you can use when the
client sends invalid JSON that can't be parsed. Use `jsonrpc2:parseerror()` to
create the appropriate error response for this purpose.

Examples:

```erlang
my_handler(<<"Foo">>, [X, Y]) when is_integer(X), is_integer(Y) ->
    {[{<<"Foo says">>}, X + Y + 42}]};
my_handler(<<"Foo">>, _SomeOtherParams) ->
    throw(invalid_params);
my_handler(<<"Logout">>, [Username]) ->
    throw({jsonrpc2, 123, <<"Not logged in">>});
my_handler(_SomeOtherMethod, _) ->
    throw(method_not_found).
```

Compatible JSON parsers
-----------------------

Any JSON encoder that returns maps

License
-------

```
Copyright 2021 Helium Systems Inc
Copyright 2013-2014 Viktor Söderqvist

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
```

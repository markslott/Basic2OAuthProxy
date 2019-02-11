# Basic Auth to OAuth Java Servlet Proxy for accessing Salesforce REST API

A a simple Java servlet that will proxy requests to the Salesforce REST API.

This proxy servlet simplifies the authentication process by presenting a simple Basic Authorization method
for passing in credentials rather than having to go through the multistep OAuth flow. This is useful for
integration scenarios where an application needs to integrate with Salesforce, but is not capable of dealing
with OAuth, but can manage HTTP Basic Auth.

## Running Locally

Recommend using Eclipse IDE and cloning this repo into a workspace. Works well locally on a Tomcat 9 server.
Be sure to set the environment variables listed in the Documentation section below

```sh
$ git clone 
$ mvn install
```
the .war file will be in the ./target directory
just use whatever deploy process you want from there...


## Deploying to Heroku

[![Deploy](https://www.herokucdn.com/deploy/button.svg)](https://heroku.com/deploy)

or if you prefer it the manual way:

```sh
$ git clone 
$ heroku create
$ heroku config:set CLIENT_ID=<your Salesforce connected app client ID>
$ heroku config:set CLIENT_SECRET=<your Salesforce connected app client secret>
$ heroku config:set TOKEN_EXPIRATION_TIME_MILLISECONDS=30000
$ git push heroku master
```

Note: On heroku, the servlet root URI is '/'. On any other app server, the servlet root will be what is specified in the web.xml

## Documentation

Refer to the Salesforce help documentation on setting up a connected app. This will need to be done prior to deploying since the servlet needs some
environment variables to be set:

CLIENT_ID - this is the OAuth client id value from the connected app configuration

CLIENT_SECRET - this is the OAuth client secret value

TOKEN_EXPIRATION_TIME_MILLISECONDS - this value will default to 10 seconds. It sets the token expiration time within the servlet. Set this value to anything smaller than
the actual timeout value in Salesforce.

There is no user interface for this application - it is just a proxy for the Salesforce REST API. To test, use a tool like Postman or curl to send
HTTP requests to the proxy servlet.  If you deployed to Heroku, then accessing the API is as simple as sending a GET request to

https://your-instance.herokuapp.com/services/data/v45.0

You will need to include your user credentials in an HTTP Basic Auth header. The proxy servlet will deal with converting those credentials into an OAuth request.
Also, set the content-type header to application/json, just like you would when using the Salesforce REST API.



## License
Copyright (c) 2018, salesforce.com, inc. All rights reserved.

Redistribution and use in source and binary forms, with or without modification, are permitted provided that the following conditions are met:

- Redistributions of source code must retain the above copyright notice, this list of conditions and the following disclaimer.
- Redistributions in binary form must reproduce the above copyright notice, this list of conditions and the following disclaimer in the documentation and/or other materials provided with the distribution.
- Neither the name of salesforce.com, inc. nor the names of its contributors may be used to endorse or promote products derived from this software without specific prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
+++
title = "GraphQL APIs and Enumeration Basics"
description = "An introduction to GraphQL"
type = ["posts","post"]
tags = [
    "grpahql",
    "api",
    "enumeration"
]
date = "2023-09-13T14:12:00"
categories = [
    "api",
    "graphql",
]
[ author ]
  name = "rob scharf"
+++

<meta http-equiv="refresh" content="0; url=https://blog.cyberadvisors.com/technical-blog/blog/graphql-apis-enumeration-basics">

This blog post serves as an introduction to GraphQL. We will shine light on how the query language functions and some basic security considerations, as well as tools and techniques to conduct basic enumeration to discover API endpoints and the underlying data schemas that power them. Let’s dive in!

What Is GraphQL?

GraphQL is an Application Programming Interface (API) query language that is packaged with a server-side runtime (such as node.js) for executing requests based on a schema defined by the developers of a given application. In 2012, GraphQL began as an in-house project by Facebook to improve newsfeed performance on mobile applications, before being released as a public, open-source language in 2015.
GraphQL API

In the years since its public release, GraphQL has emerged as a prominent alternative to traditional representational state transfer (REST) APIs. Given their reliance on fixed data structures, applications built on REST APIs often require multiple endpoints and requests to accomplish a single application procedure. The inability to define query parameters also leads to frequent “over-fetching” (receiving more data than required).

GraphQL, by contrast, features a singular endpoint that can accept sophisticated, multi-parameter queries, and accommodate flexible data structures. This reduces the need to make multiple requests to accomplish a single operation while also avoiding over-fetching by returning precisely the data needed by the application. Additionally, GraphQL is agnostic when it comes to working with specific programming languages and databases, allowing for a wide variety of use cases.

However, while GraphQL was designed primarily to function from a single endpoint, not all implementations are limited in this manner. This was illustrated during a recent engagement, where an active /app endpoint was identified in addition to the default /graphql configuration, leading to the discovery of additional sensitive non-public information (which was unavailable from the default endpoint).
GraphQL Schema

In short, GraphQL relies on a schema to outline its functionality. The schema defines the data types that the API uses and the associated fields for each, as well as resolver functions that map request fields to the specific data needed to fulfill them. With these elements specified, the GraphQL server – which is positioned between users and an external database – will accept the following operation types: queries (which returns data specified in a request), mutations (which alter data specified in a request), and subscriptions (which provide synchronous updates to application data).

Unlike a traditional REST API, GraphQL prefers to receive the POST request type to carry out all of its procedures. This is true regardless of the character (read, write, update, destroy) of the request action. However, as our primary concern is to highlight potential security vulnerabilities, it is also important to note that several popular frameworks allow for GET requests to also be used for certain actions. This can create viable Cross-Site Request Forgery and other popular client-side attacks opportunities.

Also unlike many of its REST counterparts, when GraphQL is deployed with a default configuration, it does not include native authentication functionality. In addition to the design of an access control scheme, this is a consideration that falls to the developer of the application in question. Popular authentication solutions for applications that employ GraphQL include HTTP header-based token systems, such as JSON web tokens (JWTs).

GraphQL is a strongly typed language. This means that when the server receives a request that utilizes an incorrect data type, the API is more likely to respond with an error message (with verbosity depending on configuration) than to attempt to serve a response to the request. While this is an important benefit from a security perspective, later on in this post we will discuss specific native GraphQL functionality that can be leveraged – via malformed server requests – that can lead to the disclosure of sensitive information!

GraphQL supports a wide variety of languages, as seen by the list available here. According to the 2022 State of GraphQL, developers reported most often using GraphQL for publicly exposed websites or applications (~48% of survey respondents), followed by private internal APIs (~40%), and public APIs for third-party developers (~20%). Equally, in terms of server distribution, participants indicated that they most frequently use Apollo Server (~67%), followed by Graphql.js (~31%), as well as Express-GraphQL (~28%), Yoga (12%), and Absinthe (5%).

Apollo GraphQL

Due to its popularity and robust tooling, we chose to use Apollo Server to develop a sample application that will be used to demonstrate techniques in this, and future, blog posts.

Enumerating GraphQL

While GraphQL can present a broad attack surface, it is first necessary to locate active endpoints in order to access and assess any vulnerabilities. Once an endpoint has been identified, there are multiple ways to discover the contents of the implementation’s schema without authenticated access or the ability to view the server-side source code.
Finding Endpoints

To investigate a potentially vulnerable GraphQL instance, the API endpoint must first be located. GraphQL APIs often – but not exclusively – use a single endpoint to accept all requests, as this is one of the primary benefits of using a traditional REST API. 

One option to locate valid GraphQL endpoints is to conduct a simple directory brute force attack against the root URL of a discovered web application. In the example shown below, we have employed Feroxbuster – a common Rust-based content discovery tool – alongside a list of common GraphQL endpoints from SecLists:

feroxbuster -u http://192.168.100.172:3001 -w /opt/SecLists/Discovery/Web-Content/graphql.txt

Note that, in the screenshot above, the valid graphql endpoint located at /graphql returned an HTTP status code of 400 (Bad Request). This is expected behavior from GraphQL, which will return a 400 response (“GET query missing.”) to most requests submitted without a properly formatted request body and Content-Type header, regardless of request method. Thus, when fuzzing for GraphQL endpoints, we recommend ensuring that 400-coded responses are not being filtered out by your tool of choice.

Running an Active Scan from Burp Suite’s SiteMap tab will find common GraphQL URL paths like /graphql, /api, /graphql/api, and /v1/graphql. Popular tools such as graphql-cop – and even manually browsing a web application while proxying requests through Burp Suite – can also find the location of vulnerable GraphQL deployments. 

Basic Universal Queries

As, at their core, GraphQL APIs rely on typed objects and queries to deliver basic functionality, we can leverage this by formulating simple queries to simultaneously determine if introspection is enabled. The first query we will look at is what PortSwigger calls a “universal” query. By default, GraphQL reserves the __typename field, which returns the type of a given object. We can take advantage of this by asking the server for the typename of the basic query type, which will be present in all active GraphQL instances. Our request looks like:

{ "query": "query{__typename}"}

As the server successfully returns the Query typename, we have confirmed that a GraphQL instance is operating at the specified endpoint.

As an alternative, we could request the name field for each of the application’s queryTypes.

{ "query": "{__schema{queryType{name}}}"}

Finally, we have the option of sending the following query, which requests the name attribute of all types – both implicitly and explicitly defined in the application’s schema. This option produces a bit more verbose output than the previous two, though the data contained within may ultimately be more useful.

{ "query": "{__schema{types{name}}}"}

Introspection

GraphQL ships with native introspection functionality that, as the name implies, allows for users to send a specially formed query to the API which will respond with all available information about its own application’s data schema in a human-friendly format. While this is undoubtedly a useful tool for developers to use when creating or debugging a web application, introspection represents a significant security risk when it is left enabled in production or unsecured development environments.

With introspection enabled, malicious actors (or any user which can access the API endpoint) have the ability to send these queries to the server, without encountering any native authentication or authorization measures. The server’s responses can not only reveal the entirety of the API schema employed but also the existence of sensitive fields and/or specific application functionality that can be abused by would-be attackers.

Check If Introspection Is Enabled

GraphQL deployments rely on a type system to define its schema, which outlines the character of objects accessible by the application, how they are defined, and which operations (queries, mutations, and subscriptions) are available to access and interact with them. Through its introspection capabilities, users can request a variety of data, including information related to the application’s schema, available operations, and even the format of individual types. 

We will first take a look at the methods for manually identifying if introspection is enabled for a GraphQL instance before taking a look at some of the tools available for automating this process.

Full Introspection Query

Following a successful response to one of the above queries, it is important to verify if the API is running with GraphQL’s introspection feature enabled. To do so, we can send a full introspection query, which can look like the following:

{"query": "query IntrospectionQuery{__schema{queryType{name}mutationType{name}subscriptionType{name}types{...FullType}directives{name description locations args{...InputValue}}}}fragment FullType on __Type{kind name description fields(includeDeprecated:true){name description args{...InputValue}type{...TypeRef}isDeprecated deprecationReason}inputFields{...InputValue}interfaces{...TypeRef}enumValues(includeDeprecated:true){name description isDeprecated deprecationReason}possibleTypes{...TypeRef}}fragment InputValue on __InputValue{name description type{...TypeRef}defaultValue}fragment TypeRef on __Type{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name}}}}}}}}"}

If the feature is enabled, as is shown here, the GraphQL API’s schema will be returned in a human-readable (and exportable) format.

However, if we find introspection to be disabled, the GraphQL API will return a response similar to:

While, in this case, we may be unable to view the entire data schema via introspection, many GraphQL implementations natively provide functionality that can facilitate the disclosure of part, if not all, of the API schema. We cover this in the section dedicated to “field suggestions” below.
InQL Burp Suite Extension

For a more thorough inspection of GraphQL functionality, there is also the InQL Extension, available in both the professional and community edition BApp Stores. This extension provides a more convenient way to enumerate and interact with GraphQL endpoints.

Some of its features include:

    When actively scanning a host, InQL can determine whether introspection and field suggestions (covered below) are enabled on GraphQL endpoints.
    The InQL tab – available for requests in Burp Repeater – facilitates a more user-friendly method for viewing GraphQL queries and changing a query’s associated variables.
    One-click modification of request type, as well as the ability to transform query data into the proper format when switching from POST to GET requests, or vice versa. This is useful for testing whether a GraphQL server is validating a request’s content type, which is typically an application/JSON sent via a POST request. 
    A local, in-browser GraphiQL development console that can be launched from a GraphQL query listed in the Target’s SiteMap. 
    A means to view all queries and mutations via the InQL Scanner tab, which accepts either the URL for a GraphQL endpoint or a file containing the JSON retrieved from a full introspection query. 

At the time of publication, the current version of InQL available in the Burp Suite App Store is 4.0.6. The current version offered by the InQL developers through the InQL GitHub repository is 5.0. There are instructions in their README for building and adding the latest InQL extension to Burp Suite, but for the purposes of this demonstration, we will be using the version currently available in the Burp Suite App Store. 

With the InQL extension loaded, Burp Suite’s Active Scan functionality will identify whether or not introspection is enabled. Beyond this, the InQL Scanner tab displays queries and mutations in a schema. This is achieved by either manually inputting the address of a GraphQL endpoint (e.g., http://192.168.100.172:3001/api/graphql) or by supplying a file that contains the schema contents in JSON format, which can be retrieved via a full introspection query. Both of these cases are illustrated below.

After the endpoint has been discovered, you can open the InQL Scanner tab and paste in the full URL to view the various queries made by the application. In some cases, the endpoint itself won’t load the schema but providing the full path to the schema.json file might work, for example: 

http://192.168.100.172:3001/graphql/schema.json 

In addition to loading the schema from a GraphQL endpoint, you also have the option to copy all of the JSON from a full introspection query, paste that into a file, and then load that file into the InQL Scanner.

Once InQL’s Scanner is populated with queries, you can send any of those as a request in Repeater by right-clicking in the query pane and then Send to Repeater.
Once InQL’s Scanner is populated with queries, you can send any of those as a request in Repeater by right-clicking in the query pane and then Send to Repeater. White oak security image.

It’s also possible to copy all of the text from the InQL Scanner’s query pane and paste that directly into the InQL tab located in Repeater.

Outside of Burp Suite, initial scanning can be done with graphql-cop, which will output a list of many common GraphQL vulnerabilities and misconfigurations.

./graphql-cop.py -t http://localhost:3001 -f

Remediation/Advisory – Disable Introspection

When setting up your GraphQL server, it is best practice to disable both the development console and introspection outside of a development environment.

For greater flexibility and control over when to enable or disable introspection, the graphql-disable-introspection package can be added via node package manager (npm) as middleware to your Express-based GraphQL server:

npm install -save graphql-disable-introspection

After the package is installed, only a few changes are required in your server-side code to disable introspection. The following is an example specific to the Apollo GraphQL server, but the implementation is similar in other node.js projects:

const disableIntrospection = require('graphql-disable-introspection');
server = new ApolloServer({
    typeDefs,
    resolvers,
    validationRules: [disableIntrospection] //additional line to disable introspection
});

GraphQL Schema Visualizers

When a GraphQL server has introspection enabled there are a number of online and offline options to get a more structured representation of the API’s queries, mutations, and data types. A few of the more widely used tools include InQL’s in-browser IDE, Apollo’s GraphQL Playground, Apollo Studio available at the GraphQL endpoint when running Apollo Server in dev mode, and GraphQL Voyager. 

To launch InQL’s GraphiQL development console from Burp Suite, right-click on the request and navigate to Extensions -> InQL Introspection GraphQL Server -> inql: Send to GraphiQL.

That will open the in-browser GraphiQL IDE running on your local host.

In the IDE’s left pane, the introspection query along with any other queries that have already been executed through manually browsing the site will show up as tabs. Clicking on the tabs will reveal the query’s associated data in the right pane. 

The Documentation Explorer icon in the upper left corner of the IDE will open the Docs pane where you can browse all available queries, mutations, and schema types. 

If an Apollo Server is running in development mode, then the following landing page will be available at the application’s GraphQL endpoint. 

Clicking on Query your server takes you to Apollo Studio sandbox, a browser-based IDE with offline capabilities where you can view and interact with a GraphQL schema. 

When running an Apollo Server in production mode the option to connect to Apollo Studio is removed, however, the landing page along with the provided curl command will remain on the page. It is recommended that this landing page either be hidden or customized, following the instructions in the Apollo Server Docs. 

Finally, GraphQL Voyager creates an interactive graph of a GraphQL API and is useful for seeing an overall view of the entire schema at once. 

Loading a GraphQL schema is as simple as pasting in the response from a full introspection query. 

To build the GraphQL Voyager application locally you will need Node.js and Docker installed. The application comes pre-loaded with 4 preset schemas from GitHub, Yelp, Shopify, and even Star Wars that allow you to preview queries and data in more complex schemas. 

While there are GraphQL schema visualizers that are available online, running a local instance is preferable so as not to run the risk of leaking sensitive data publicly. 

GraphQL Field Suggestions

Unlike competing API frameworks that respond to invalid queries by simply returning traditional HTTP Response Codes (such as the classic “400 Bad Request”), GraphQL provides development-friendly functionality known as “field suggestions.” GraphQL instances with field suggestions enabled will suggest amendments to malformed user requests via verbose error messages. These error suggestions come in the form of a “Did you mean…?” message. For example:

GraphQL instances with field suggestions enabled will suggest amendments to malformed user requests via verbose error messages. These error suggestions come in the form of a “Did you mean…?” message. Shown here in this white oak security pentesters.

Despite the obvious security risks involved, field suggestions remain a feature of several prominent GraphQL distributions and can be observed in a large number of public-facing deployments across the internet, though it does not appear in the “vanilla” GraphQL spec. 

While not all query attempts will be met with a suggestion (for example, root query operations), it presents a large enough attack surface for malicious actors to potentially glean critical information about a given GraphQL deployment. With InQL enabled in Burp Suite, actively scanning a GraphQL endpoint with field suggestions will produce the following finding:

For those not using Burp Suite, Clairvoyance is a popular CLI tool for discovering the schema of GraphQL instances operating with introspection disabled. It uses “field stuffing” (similar to credential stuffing) with a provided wordlist to generate queries that leverage field suggestions to discover valid elements of the API schema, without relying on introspection. Clairvoyance outputs a JSON file that can be ingested by a variety of analytical and visualization tools.

Remediation

At the time of publication, there is no specific native capacity in Apollo Server (or its peer distributions that provide similar functionality) to disable field suggestions. This GitHub thread, originally posted in 2019, outlines the approach of the project maintainers and progress made (including this proposed Pull Request from January 2022) in providing the ability to disable field suggestions. A couple of potentially viable community-sourced solutions can also be found in this GitHub thread. Beyond this, software such as GraphQL Armor provides avenues for remediation through, for example, its “Block field suggestions” plugin, though results may vary across different GraphQL frameworks and software versions.

GraphQL APIs & Enumeration

We hope that you have enjoyed this blog post, which has served as an introduction to GraphQL. In it, we have briefly discussed how the query language functions and basic security considerations, as well as tools and techniques to conduct basic enumeration to discover API endpoints and the underlying data schemas that power them. For more information on GraphQL, including common vulnerabilities and attack vectors, we suggest starting with PortSwigger’s Web Security Academy and Black Hat GraphQL: Attacking Next Generation APIs by Dolev Farhi and Nick Aleks, both of which were used as references in compiling this blog post.
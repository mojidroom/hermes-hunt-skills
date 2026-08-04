# Hacking GraphQL endpoints in Bug Bounty Programs – YesWeHack

Source: https://www.yeswehack.com/learn-bug-bounty/hacking-graphql-endpoints

## Table of Contents

- Hacking GraphQL endpoints with introspection, query, mutation, batching attacks
- Outline
- What is GraphQL?
- GraphQL security risks
- Examples of GraphQL endpoints
- Abusing GraphQL introspection
- How to perform GraphQL introspection
- GraphQL introspection disabled? Try a fuzzing attack instead
- GraphQL query vulnerabilities
- GraphQL mutation vulnerabilities
- Executing a batching attack in GraphQL
- Essential GraphQL tools
- GraphQL Voyager
- InQL (Burp Suite extension)
- Mitigation & best practices for GraphQL security
- Conclusion
- References
- Footer
- Products
- Researchers

## Content

GraphQL is an increasingly popular alternative to REST APIs, but its greater versatility also offers rich hacking opportunities.
For instance, the greater complexity of this query language creates scope for vulnerabilities with significant potential to expose significant volumes of sensitive data.
Moreover, popular use cases – such as mobile, SaaS and ecommerce applications as well as rapidly evolving software – mean that the organisations leveraging GraphQL sometimes have relatively significant financial resources.
Taken together, these observations mean that GraphQL vulnerabilities can sometime attract relatively significant rewards on Bug Bounty Programs.
This guide reveals practical techniques – from introspection queries to mutation manipulation – for identifying and exploiting GraphQL vulnerabilities and gaining an edge over your fellow bug hunters or pentesters.
Outline
What is Graphql?
GraphQL security risks
Examples of GraphQL endpoints
Abusing GraphQL introspection
How to perform GraphQL introspection
Introspection Disabled? Try a fuzzing attack instead
GraphQL query vulnerabilities
GraphQL mutation vulnerabilities
Executing a batching attack in GraphQL
Essential GraphQL tools
GraphQL Voyager
InQL (Burp Suite extension)
Mitigation & best practices for GraphQL security
Conclusion
References
What is GraphQL?
GraphQL is a powerful query language developed by Facebook and open-sourced in 2015. It allows clients to request exactly the data needed from an API in a single query, thus avoiding common REST API pitfalls like over-fetching or under-fetching.
GraphQL can handle complex, nested queries and real-time data subscriptions, making it an ideal choice for modern web and mobile applications. (This
YouTube short
explains the difference in an amusing way).
Benefits of GraphQL include improved performance, flexibility in data retrieval, and enhanced developer productivity. Built-in introspection tools allow developers to easily explore and understand API schemas, simplifying debugging and integration with backend systems. These advantages explain why growing numbers of companies are adopting GraphQL as they modernise their infrastructure.
This article focuses exclusively on potential attacks against GraphQL endpoints and does not serve as a development tutorial. For detailed development resources, please consult the
GraphQL website
.
GraphQL security risks
Despite GraphQL’s advantages, it also presents a number of security risks due to the complexity and flexibility of its queries. For instance, attackers can (unless explicitly restricted) query deeply nested or unexpected fields, perform introspection queries that reveal entire API schemas, and perform multiple operations in a single request that potentially bypass rate limits and enable simultaneous malicious operations.
Common vulnerabilities found on GraphQL endpoints include information disclosure, business logic error, insecure direct object references (IDOR) and improper access control vulnerabilities.
Examples of GraphQL endpoints
It’s impractical to list all permutations of endpoints associated with a GraphQL instance. However, many GraphQL APIs, especially those built with frameworks like
Apollo
, commonly use standard endpoint paths such as:
1
/
v1
/
explorer
2
/
v1
/
graphiql
3
/
graph
4
/
graphql
5
/
graphql
/
console
/
6
/
graphql
.
php
7
/
graphiql
8
/
graphiql
.
php
9
(
...
)
A comprehensive list can be found on
SecLists
. Another effective method to identify hidden GraphQL endpoints involves searching JavaScript files for keywords like "query", "mutation", or "graphql". This can reveal unofficial or decommissioned GraphQL endpoints.
Abusing GraphQL introspection
GraphQL introspection lets users query an API for schema details, effectively providing self-documentation on available types, fields, queries and mutations.
This helps developers understand and interact with the API more efficiently.
If introspection is enabled on the target, that is good news. It means you gain a deeper knowledge of the API and can target specific vulnerabilities with greater precision.
How to perform GraphQL introspection
During a pentest, we can use the payload below to perform a GraphQL introspection (if this feature is enabled) on our target:
1
{
__schema
{
queryType
{
name
}
mutationType
{
name
}
subscriptionType
{
name
}
types
{
...
FullType
}
directives
{
name description locations args
{
...
InputValue
}
}
}
}
fragment
FullType
on __Type
{
kind name description
fields
(
includeDeprecated
:
true
)
{
name description args
{
...
InputValue
}
type
{
...
TypeRef
}
isDeprecated deprecationReason
}
inputFields
{
...
InputValue
}
interfaces
{
...
TypeRef
}
enumValues
(
includeDeprecated
:
true
)
{
name description isDeprecated deprecationReason
}
possibleTypes
{
...
TypeRef
}
}
fragment
InputValue
on __InputValue
{
name description type
{
...
TypeRef
}
defaultValue
}
fragment
TypeRef
on __Type
{
kind name ofType
{
kind name ofType
{
kind name ofType
{
kind name ofType
{
kind name ofType
{
kind name ofType
{
kind name ofType
{
kind name
}
}
}
}
}
}
}
}
The server should respond with the full schema (including query, mutation, objects and fields). While the schema is typically displayed in JSON, it often becomes unreadable due to its complexity and nested structure. In my experience, once you have retrieved the schema, the best way to simplify analysis is to import it into a tool like “
GraphQL Voyager
” (
which we will talk more about later
).
GraphQL introspection disabled? Try a fuzzing attack instead
GraphQL’s introspection is sometimes disabled for unauthorised users as a security measure. However, GraphQL’s field suggestion feature, which is enabled by default, can inadvertently reveal schema information too. The feature helps developers by suggesting corrections for mistyped fields, so if you query a field and include a deliberate typo, GraphQL will suggest fields that closely match your intended query – inadvertently facilitating your recon efforts.
Note: This abuse of field suggestions does not, technically, constitute potential vulnerabilities, since the behaviour is intended. Nevertheless, for hackers this feature is an invaluable way to gain insight into GraphQL’s schema – especially when the introspection feature is inaccessible.
It’s wise to use specialised tools rather than conducting these fuzzing attacks manually. Burp Suite Intruder is a popular option, although it requires substantial configuration to achieve accurate results for this type of attack. It’s therefore worth also trying purpose-built community tools like
Clairvoyance
and
GraphQLmap
.
GraphQL query vulnerabilities
A fundamental challenge with GraphQL is the lack of a built-in access control system. Instead, developers must write custom resolvers to map queries to the appropriate database, which can introduce vulnerabilities such as improper access control and Insecure Direct Object Reference (IDOR) flaws if not done correctly.
For example, consider a legitimate query called "currentUser" that accepts an "internalId" parameter. This query should only return information for the currently connected user, who is identified by the internalId, therefore keeping other users’ data secure:
1
query
{
2
currentUser
(
internalId
:
1337
)
{
3
role
4
name
5
email
6
token
7
}
8
}
Changing the
internalId
might retrieve another user’s data, indicating the presence of an IDOR – a common GraphQL vulnerability when access controls are not properly enforced.
Similarly, queries can be manipulated to extract unintended data. For instance, consider the following query, used by a newsletter web application:
1
query
{
2
listPosts
(
postId
:
13
)
{
3
title
4
description
5
}
6
}
If an attacker adds extra fields to this query, they may be able to extract sensitive information. This scenario underlines the critical importance of implementing strict validation and access controls in GraphQL resolvers. By using introspection or fuzzing, you might also dis
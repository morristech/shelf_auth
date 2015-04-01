## 0.5.0

* Now uses http_exception package rather than shelf_exception_response

## 0.4.0

* Upgraded dart-jwt and shelf versions

## 0.3.0

* BREAKING CHANGE: Made sessionIdentifier mandatory for jwt sessions.
    * If you are using jwt sessions in production then release a version with
      0.2.6 first. Otherwise you will get errors from any existing sessions
      as they won't have sessionIdentifiers.

## 0.2.6

* Added an optional sessionIdentifier

## 0.2.5

* Added support for excluding some requests from authorisation checks

## 0.2.4

* Added authenticated only authoriser

## 0.2.3+1

* Added some logging

## 0.2.3

* Added authorisation support

## 0.2.2+1

* some doco

## 0.2.2

* Exposed zone functionality via an spi so other libs can manually set 
auth context

## 0.2.1

* Added builder to simplify creating authentication middleware. Use the new 
`builder` function to create a builder

## 0.2.0

* Added AuthenticatedContext as a Zone variable. Available via a new function 
`authenticatedContext()`

Note the AuthenticationMiddleware class is no longer exposed. If you depended
on it then this change is backwards incompatible. Otherwise all good

## 0.1.0+1

* Added missing dependency on shelf_path

## 0.1.0

* Added Jwt Session Mechanism
* SessionHandlers now have an associated Authenticator

## 0.0.3

* Added Basic Auth
 
## 0.0.1

* First version 

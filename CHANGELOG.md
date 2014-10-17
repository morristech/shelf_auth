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

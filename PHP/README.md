# PHP WebSSO
This is a really basic implementation of a PHP webSSO client.

## Notes on Implementations
I would recommend using Guzzle HTTP with a middleware to automatically re-try failed connections to the webSSO service -- something like [this](https://github.com/NIT-Administrative-Systems/SysDev-EventHub-PHP-SDK/blob/master/src/Guzzle/RetryClient.php).

It's also worth considering doing webSSO authentication once for a session and then creating an app-specific login cookie, e.g. we let Laravel set its own login cookie and just validate that on subsequent requests. This is a performance boost, as we don't need to constantly go back to the webSSO API for every page load.
# Agentless WebSSO Examples
This is a repository that contains example implementations of Northwestern's webSSO authentication. The examples have been for [The New WebSSO](https://www.it.northwestern.edu/about/it-projects/websso-upgrade/index.html).

It is also worth noting that the new webSSO supports OpenID Connect (which is similar to OAuth) as an integration option.

We are happy to accept pull requests with more examples!

## Agentless?
We've relied on the webSSO agent to provide authentication in the past. This is a module that gets plugged into the web server (e.g. Apache) and acts as a request interceptor, only allowing an HTTP request to make it all the way to your application if a valid webSSO session is detected. It'll add the netID in as a header and your app can receive that trusted value.

This repo is an example of agentless setups -- webSSO without having to install that additional module. The upside to this approach is that developers have more control over their app's authentication process (e.g. you can have non-netID auth methods instead of the agent's blanket requirement). It also gives us the capability to do webSSO in non-traditional environments (e.g. AWS lambda) that don't have a supported web server.

## Setup
To authenticate a webSSO session, there are a few prerequisites:

1. Your app must be served from a `northwestern.edu` domain (cookie domain restrictions)
1. Your app must be served over HTTPS (cookie has the secure flag)
1. You must register in the API Service Registry (so we can track who has an agentless app -- wasn't fun figuring it out for the webSSO upgrade)

You no longer need to do anything extra for Duo MFA.

## Beyond Authentication
WebSSO only gives you a netID. If you need directory information (e.g. name, email, staff/student/faculty status), you will need to use the [DirectorySearch service](https://apiserviceregistry.northwestern.edu). This beyond the scope of our humble demo repository.

## Credits
Special thanks goes to the McCormick IT group, who wrote the first agentless implementation that I'd seen. All of this is just copping off their code ;)

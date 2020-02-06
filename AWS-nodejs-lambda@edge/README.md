# AWS Lambda@Edge NodeJS WebSSO
This is a [Lambda@Edge](https://docs.aws.amazon.com/lambda/latest/dg/lambda-edge.html) function that works with AWS' CloudFront CDN service. It runs on each incoming web request.

The Lambda@Edge functions have additional restrictions on their size, memory, and runtime limits that are more stringent than a normal Lambda. See the AWS documentation for the details, but the general rule is "as small and fast as humanly possible".

To deploy this to AWS, you need to package it up as a zip file with its dependencies. This package has two sets of dependencies: the ones it needs to run, and some additional dependencies for running tests. You only need to package up the first set when deploying.

```sh
# For packaging to upload to AWS
$ npm ci # ci is more strict than install & intended for use in automated builds
$ zip it up somehow? # I use terraform to do it :V

# Or, if you want to change it locally:
$ npm install
$ npm test
```

You can add in authorization or whatever else you need.

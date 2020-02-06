<?php
$netid = 'not authenticated';

$apigeeApiKey = 'your-apigee-api-key-for-agentless-sso-here';
$webSSOApi = 'https://northwestern-test.apigee.net/agentless-websso/validateWebSSOToken';

/**
 * Send the user to the online passport login page.
 */
function redirectToLogin()
{
    $redirect = urlencode('https://' . $_SERVER['SERVER_NAME'] . '/' . $_SERVER['REQUEST_URI']);

    header("Location: https://uat-nusso.it.northwestern.edu/nusso/XUI/?realm=northwestern#login&authIndexType=service&authIndexValue=ldap-and-duo&goto=$redirect");
    exit;
}

/**
 * Get the value of a cookie, if it exists.
 */
function getCookieValue($name)
{
    $token = null;
    if (array_key_exists($name, $_COOKIE) == true) {
        $token = $_COOKIE[$name];
    }

    return $token;
}

// Do we have a session?
$token = getCookieValue('nusso');
if ($token == null) {
    redirectToLogin();
}

/*
* Is the session valid?
*
* You can use any HTTP library you want here.
* I'm using stream_context_create since it's a PHP built-in,
* but I recommend using Guzzle instead!
*/
$context  = stream_context_create([
    'http' => [
        'method' => 'POST',
        'header' => implode("\r\n", [
            "Content-Length: 0",
            "apikey: $apigeeApiKey",
            "webssotoken: $token",
            "requiresMFA: true",
            "goto: ", // not using this functionality
        ]),
        'ignore_errors' => true,
    ],
]);

$result = file_get_contents($webSSOApi, false, $context);
if ($result === false) {
    redirectToLogin();
}

$result = json_decode($result, JSON_OBJECT_AS_ARRAY);
if (array_key_exists('fault', $result)) {
    echo "Your apigee key is not valid:<br><pre>";
    print_r($result);
    echo "</pre>";
    die();
}

if (array_key_exists('netid', $result) === false) {
    redirectToLogin();
}

$netid = $result['netid'];
?>

<!DOCTYPE html>
<html lang="en">
  <head>
    <!-- Required meta tags -->
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1, shrink-to-fit=no">

    <!-- Bootstrap CSS -->
    <link rel="stylesheet" href="https://stackpath.bootstrapcdn.com/bootstrap/4.1.3/css/bootstrap.min.css" integrity="sha384-MCw98/SFnGE8fJT3GXwEOngsV7Zt27NXFoaoApmYm81iuXoPkFOJwJ8ERdknLPMO" crossorigin="anonymous">

  </head>
  <body>
    <h1>Hello, world!</h1>
    <p>I am authenticated as <strong id='netid'><?= $netid; ?></strong>!</p>

    <script src="https://code.jquery.com/jquery-3.3.1.slim.min.js" integrity="sha384-q8i/X+965DzO0rT7abK41JStQIAqVgRVzpbzo5smXKp4YfRvH+8abtTE1Pi6jizo" crossorigin="anonymous"></script>
    <script src="https://cdnjs.cloudflare.com/ajax/libs/popper.js/1.14.3/umd/popper.min.js" integrity="sha384-ZMP7rVo3mIykV+2+9J3UJ46jBk0WLaUAdn689aCwoqbBJiSnjAK/l8WvCWPIPm49" crossorigin="anonymous"></script>
    <script src="https://stackpath.bootstrapcdn.com/bootstrap/4.1.3/js/bootstrap.min.js" integrity="sha384-ChfqqxuZUCnJSK3+MXmPNIyE6ZbWh2IMqE241rYiqJxyMiZ6OW/JmZQ5stwEULTy" crossorigin="anonymous"></script>
  </body>
</html>

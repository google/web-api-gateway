# Web Api Gateway

Web Api Gateway allows you to selectivley share API access with partners.

# Setup Guide

## 1. Acquire Advertising Account Access

To manage an advertising account, you will need permission to do so. You likely
already have this.

## 2. Acquire API Access

You will need OAuth2 access to the api you wish to connect to. If you have
access, you will have a “Client ID”, and a “Client Secret”. Where these are
located will vary by website, but can be accessed with the account that was
given access to the API.

## 3. Server

You will need somewhere to run Web Api Gateway. Your options include one of the
following:

*   A virtual machine running on a cloud provider. Recommended, this is what
    this guide will follow.
*   Kubernetes. If you have an existing Kubernetes cluster, you may leverage
    that to run your service.
*   An on premise machine in your own data center.

Your choice must be capable of:

*   Running a docker container.
*   Providing persistent storage for that container.
*   Exposing https ports to the internet.

### Starting your VM.

On your cloud provider of choice, create a new VM instance.

We recommend:

*   Choosing a low powered VM. No need to go overboard on size and capabilities.
    This is a fairly simple, low load server. If anything becomes a bottleneck,
    it is likely the network, so low ram and processing power are fine. You can
    upgrade later if that’s a problem.
*   The latest version of Ubuntu, though your favorite variant of linux will
    likely be fine.

## 4. Expose to external internet

If you’re not using a cloud based VM, this will depend heavily on your local
setup.

In your cloud provider, your VM must have a reserved static external IP address.
This may either be an option when creating/editing your VM, or it may be a
separate option after creation.

You also must set any firewall settings to expose port 443. If you are using
Let’s Encrypt to provide a certificate for https, you must also expose port 80.

## 5. Domain Name

You probably have an existing domain name which you can use a subdomain from.
Use your favorite domain name registered, and add an “A” record which points to
the domain name of your choice to the external IP address from the previous
step. For the remaining examples, replace “web-api-gateway.example.com” with
your actual domain.

## 6. SSL Certificate

You must set up certificates for your Web Api Gateway. This allows clients to
connect to Web Api Gateway with HTTPS, and know they’re talking to the correct
server. If you have an existing process for creating and managing certificates,
you will likely want to use that.

The easiest way to quickly get a certificate for the domain used for Web Api
Gateway is by using Let’s Encrypt.

1.  Go to https://certbot.eff.org/
2.  Select “None of the above” for your choice of Software
3.  Select the system you’re using.
4.  You’ll want to use the “--standalone” method with the additional flag
    “--preferred-challenges http”. This will use the standard http port, and
    won’t conflict with web-api-gateway. You can ignore the instructions to use
    “--webroot“, as web-api-gateway doesn’t serve any local files.

    Our command looks like this: (*replace the example url with your url*)

    ```
    sudo certbot certonly --standalone --preferred-challenges http -d web-api-gateway.example.com
    ```

    This should give you feedback like the following:

    ```
    sudo certbot certonly --standalone --preferred-challenges http -d web-api-gateway.example.com
    Saving debug log to /var/log/letsencrypt/letsencrypt.log
    Plugins selected: Authenticator standalone, Installer None
    Obtaining a new certificate
    Performing the following challenges:
    http-01 challenge for web-api-gateway.example.com
    Waiting for verification...
    Cleaning up challenges

    IMPORTANT NOTES:
     - Congratulations! Your certificate and chain have been saved at:
       /etc/letsencrypt/live/web-api-gateway.example.com/fullchain.pem
       Your key file has been saved at:
       /etc/letsencrypt/live/web-api-gateway.example.com/privkey.pem
       Your cert will expire on 2018-12-18. To obtain a new or tweaked
       version of this certificate in the future, simply run certbot
       again. To non-interactively renew *all* of your certificates, run
       "certbot renew"
     - If you like Certbot, please consider supporting our work by:

       Donating to ISRG / Let's Encrypt:   https://letsencrypt.org/donate
       Donating to EFF:                    https://eff.org/donate-le
    ```

    If you encountered a problem related to “binding to port 80”, your vm may
    already have bound a web server to port 80. If it’s apache, you can stop it
    with:

    ```
    sudo /etc/init.d/apache2 stop
    ```

5.  Verify that your certs are present by running: (*replace the example url
    with your url*)

    ```
    ls /etc/letsencrypt/live/web-api-gateway.example.com/
    ```

6.  Let’s Encrypt certificates only last for 90 days. However certbot should
    have set up a cron job to automatically renew it.

## 7. Getting Web Api Gateway

For the current iteration, the code is located at:
https://partner-code.googlesource.com/web-api-gateway Create an account (just
log in with your Google work account) on this website, and send us an email
requesting access to the Web Api Gateway repository.

### Install Prerequisites:

#### Git:

Git is a code storing program, which will be able to retrieve a current copy of
Web Api Gateway’s source code. If you’re using the suggested Ubuntu VM approach,
run this command to install Git:

```
sudo apt install git-all
```

#### Curl:

Curl retrieves web pages, is just used to install Docker:

```
sudo apt install curl
```

#### Docker:

Dockers handles building and running Web Api Gateway. If you’re using the
suggested Ubuntu VM approach, run these commands to install Docker:

```
curl -fsSL get.docker.com -o get-docker.sh
sh get-docker.sh
```

### Clone the code:

Go here to generate git credentials for partner-code:
https://partner-code.googlesource.com/new-password

Insert the given command in your terminal.

The command to run will be roughly in the form of:

```
eval 'set +o history' 2>/dev/null || setopt HIST_IGNORE_SPACE 2>/dev/null
 touch ~/.gitcookies
 chmod 0600 ~/.gitcookies

 git config --global http.cookiefile ~/.gitcookies

 tr , \\t <<\__END__ >>~/.gitcookies
partner-code.googlesource.com,FALSE,/,TRUE,1234,o,git-user.example.com=1xxxssyyy
partner-code-review.googlesource.com,FALSE,/,TRUE,1234,o,git-user.example.com=1xxxssyyy
__END__
eval 'set -o history' 2>/dev/null || unsetopt HIST_IGNORE_SPACE 2>/dev/null
```

Next you will create a local copy of Web Api Gateway.

```
cd ~
git clone https://partner-code.googlesource.com/web-api-gateway
```

Only If you already have the code copied, and are updating to a new version,
instead run:

```
cd ~/web-api-gateway
git pull

```

Create a docker image for running in docker:

```
cd ~/web-api-gateway
sudo docker build -t web-api-gateway .
```

## 8. Running Web Api Gateway

Now you’re all set to start the server: (*replace the example url with your
url*)

```
cd ~/web-api-gateway
sudo docker run \
  --publish 443:443 \
  --name web-api-gateway \
  -d \
  -it \
  --rm \
  --volume /etc/letsencrypt/live/web-api-gateway.example.com/:/etc/letsencrypt/live/web-api-gateway.example.com/ \
  --volume /etc/letsencrypt/archive/web-api-gateway.example.com/:/etc/letsencrypt/archive/web-api-gateway.example.com/ \
  --volume /etc/webapigateway/config/:/etc/webapigateway/config/ \
  web-api-gateway \
  --certFile=/etc/letsencrypt/live/web-api-gateway.example.com/fullchain.pem \
  --keyFile=/etc/letsencrypt/live/web-api-gateway.example.com/privkey.pem
```

Verify that the container is running by:

```
sudo docker container ls
```

If the container did not start successfully, remove `-d` (which causes the
docker container to detatch from your shell) from the above command. This will
show the output of the container as it is trying to start, including any error
notices. This can help you determine what is causing the startup problems.

### If you're not using Docker

Web Api Gateway requires access to three files:

*   fullchain.pem
    *   Used in ssl/https
    *   By default looks for the file at `/etc/webapigateway/cert/fullchain.pem`
    *   The path can be changed using the flag `certFile`
*   privekey.pem
    *   Used in ssl/https
    *   By default looks for the file at `/etc/webapigateway/cert/privkey.pem`
    *   The path can be changed using the flag `keyFile`
*   The config.
    *   Used to store the accounts and credentials for access.
    *   If the Web Api Gateway is started and this file does not exist, the
        server will start but only return errors. If you start the setuptool, it
        will create a new config. If you're running with Docker (or Kubernetes),
        it's recommended that you let Docker build everything, run the setuptool
        in the container, then restart the container.
    *   By default looks for the file at `/etc/webapigateway/config/config.json`
    *   The path can be changed using the flag `configpath` (this works with the
        setuptool too.)

## 9. Setting up your configuration

In order to complete these steps, you will need the following:

*   Values provided by your API access (from step 2):
    *   Client Id
    *   Client Secret
*   Values that are dependant on the connection you're creating. These are
    typically provided by remote client which is accessing web-api-gateway.
    *   Auth Url
    *   Token Url
    *   Scopes
    *   Service Url

This will start the interactive command line setup tool.

```
sudo docker exec --interactive web-api-gateway /go/bin/setuptool
```

When first started, you will be prompted for the domain name you chose. For our
example, this is https://web-api-gateway.example.com. From there, you will be at
the main menu.

First, choose Add Service (option 3). This will prompt you for several values.
For “client id” and “client secret”, you will want to use the values obtained in
step 2. These are your personal API tokens. For the others, refer to the start
of this step.

After creating a service, choose “Add new account” (option 3). The service URL
also should use a value from the start of this step. It is required you log into
the account you wish to manage (step 1), and enter the authentication token that
you are given. From the service level view (where you can create accounts.) use
“back” (option 0), to go back to the main menu. From here, using “back” again
will save and exit.

web-api-gateway does not automatically load new configurations, so you must
restart the server.

```
sudo docker restart web-api-gateway
```

## 10. Retrieve Account Key to connect a client

When you are asked for an account key to connect an application to the Web Api
Gateway, you can retrieve it using the same command as used to setup:

```
sudo docker exec --interactive web-api-gateway /go/bin/setuptool
```

At the main menu, run “Retrieve Account Key”, choose the account you want to
link, and copy the Account Key that is provided.

Use this to link a remote client to the web-api-gateway. You will be prompted
for the account key from the remote service that you’re using.

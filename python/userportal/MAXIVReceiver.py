#!/usr/bin/env python
import pika

def authenticate(url, user, password, site, proxies):
    r = requests.post(url + '/authenticate?site=' + site, headers={'content-type': 'application/x-www-form-urlencoded'}, proxies=proxies, data={'login': user, 'password': password}, verify=False)

    token = (json.loads(r.text)['token'])

    return token


def updatebyproposal(token, proposal):
    playload = {
                'proposal'  :proposal
    }
    r = requests.post(url + '/' +token + '/proposal/{proposal}/update', headers={'content-type': 'application/x-www-form-urlencoded'}, proxies=proxies, data=payload, verify=False)
    print(r.text)



if __name__ == "__main__":

        config = ConfigParser.ConfigParser()
        credentialsConfig = ConfigParser.ConfigParser()

        # Configuration files
#       config.read('ispyb.properties') 
#       credentialsConfig.read('credentials.properties')
        script_dir = os.path.dirname(os.path.realpath(__file__))
        config.read(script_dir +'/ispyb.properties')
        credentialsConfig.read(script_dir +'/credentials.properties')

        user = str(credentialsConfig.get('Credential', 'user'))
        password = str(credentialsConfig.get('Credential', 'password'))
        site = str(credentialsConfig.get('Credential', 'site'))

        url = str(config.get('Connection', 'url'))
        proxy_http = str(config.get('Proxy', 'http'))
        proxy_https = str(config.get('Proxy', 'https'))

        myLogger.printConfiguration(user, password, url)


        proxies = {
          'http': proxy_http,
          'https': proxy_https,
        }

        rabbitmqUser = str(credentialsConfig.get('Credential', 'rabbitmqUser'))
        rabbitmqPassword = str(credentialsConfig.get('Credential', 'rabbitmqPassword'))
        rabbitmqHost = str(config.get('Connection', 'url_rabbitmq_host'))
        rabbitmqPort = str(config.get('Connection', 'url_rabbitmq_port'))

credentials = pika.PlainCredentials(rabbitmqUser, rabbitmqPassword)
parameters = pika.ConnectionParameters(rabbitmqHost, rabbitmqPort
                                   rabbitmqPort,
                                   '/',
                                   credentials)
connection = pika.BlockingConnection(parameters)
channel = connection.channel()

channel.queue_declare(queue='hello')


def callback(ch, method, properties, body):
    proposalNumber = "";
    print body
    if "Update proposal:" in body:
        a = body.split(":")
        proposalNumber = a[1].strip()
    print(" [x] Proposal to update %r" % proposalNumber )


channel.basic_consume(
    queue='hello', on_message_callback=callback, auto_ack=True)

print(' [*] Waiting for messages. To exit press CTRL+C')
channel.start_consuming()

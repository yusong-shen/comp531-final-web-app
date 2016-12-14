#!/usr/bin/env python

import requests, json, sys, pprint
pp = pprint.PrettyPrinter(indent=4)

class cc:
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

cred = {
    "username": "ys43test",
    "password": "judge-sentence-return",
}

def login(cred):
    r = requests.post(config["backend"] + "/login", json=cred)
    print r.cookies
    return r.text, r.cookies


def get(cookies, endpoint):
    url = config["backend"] + endpoint
    r = requests.get(url, cookies=cookies)
    if r.status_code != 200:
        print(cc.FAIL + ("ERROR: For GET %s received %d response code " % (endpoint, r.status_code)) + str(r.text) + cc.ENDC)
        sys.exit(1)
    return json.loads(r.text)

def put(endpoint):
    url = config["backend"] + endpoint
    r = requests.put(url)
    if r.status_code != 200:
        print(cc.FAIL + ("ERROR: For PUT %s received %d response code " % (endpoint, r.status_code)) + str(r.text) + cc.ENDC)
        sys.exit(1)
    return json.loads(r.text)

def getArticles(cookies, articleId=None):
    endpoint = '/articles'
    if articleId is not None:
        endpoint = (endpoint + "/%s") % articleId
    return checkArticles(get(cookies, endpoint))

def checkArticles(result):
    if "articles" not in result:
        print(cc.FAIL + "ERROR: GET /articles did not have \"articles\" entry" + cc.ENDC)
        print(result)
        return []
    else:
        return result["articles"]

def addArticle(body):
    r = requests.post(config["backend"] + "/article", json={'text':body})
    return checkArticles( json.loads(r.text) )

def msg(message):
    print(cc.BLUE + message + cc.ENDC)

################################################

if len(sys.argv) < 2:
    print("usage: %s README.json" % sys.argv[0])
    sys.exit(1)

with open(sys.argv[1], 'r') as f:
    config = json.loads(f.read())
    for key in config.keys():
        if config[key].endswith('/'):
            config[key] = (config[key])[:-1]

print(cc.YELLOW + ("Checking for %s site %s" % (config['netid'], config['backend'])) + cc.ENDC)

######################################
# POST /login
msg("POST /login")
r, cookies = login(cred)
pp.pprint(r)
pp.pprint("cookie sid value : %s" % cookies["sid"])


# GET /articles
articles = getArticles(cookies)
msg("GET /articles")
pp.pprint(articles)

if len(articles) < 3:
    print(cc.FAIL + ("FAIL: Expected at least 3 articles from GET /articles but found %d " % len(articles)) + cc.ENDC)
else:
    print(cc.GREEN + ("OK: GET /articles returned %d articles, expecting at least 3" % len(articles)) + cc.ENDC)

# GET /articles with given id
articleId = articles[0]["_id"]
articles = getArticles(cookies, articleId)
msg("GET /articles/%s" %articleId)
pp.pprint(articles)

if len(articles) != 1 and articles[0]["_id"] != articleId:
    print(cc.FAIL + ("FAIL") + cc.ENDC)
else:
    print(cc.GREEN + ("OK: GET /articles/%s returned correct article" % articleId) + cc.ENDC)


# GET /articles with given author
articleId = articles[0]["author"]
articles = getArticles(cookies, articleId)
msg("GET /articles/%s" %articleId)
pp.pprint(articles)

if len(articles) < 1 or articles[0]["author"] != articleId:
    print(cc.FAIL + ("FAIL") + cc.ENDC)
else:
    print(cc.GREEN + ("OK: GET /articles/%s returned correct articles" % articleId) + cc.ENDC)


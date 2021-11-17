import scrapy
from urlparse import urlparse
import whois
import csv
import json
import datetime


class QuotesSpider(scrapy.Spider):
    name = "tranco"

    def start_requests(self):
        csvfile=open("tranco_top1m.csv", newline='')
        reader = csv.reader(csvfile, delimiter=' ', quotechar='|')
        for row in reader:
            # row=['999999,satreephuket.ac.th'] of type(row)=list
            # row[0]='999999,satreephuket.ac.th'
            domainname=row[0].strip().split(',')[-1]
            yield scrapy.Request(url='https://' + domainname, callback=self.parse)
        csvfile.close()


    def parse(self, response):
        webpage = response.url.split("/")[2]
        domain = webpage.split(".")[-2]
        print(response.url)
        savepath_metadata = '%s.json' % domain
        metadata = dict()
        savepath_Clfeval = 'trancotop1m.csv'
        eval_metrics = dict()

        metadata['url'] = response.url

        eval_metrics['url_chars'] = len(response.url)

        if response.url.startswith('https'):
            eval_metrics['root_https'] = 1
        else:
            eval_metrics['root_https'] = 0

        trademarks = ['4chan','abcnews','accuweather','adobe','airbnb','alibaba','aliexpress','alliantenergy',
                      'allrecipes','amazon','americanexpress','angieslist','arstechnica','atlassian','atmosenergy',
                      'audible','azlyrics','baidu','bankofamerica','barnesandnoble','bedbathandbeyond','bestbuy',
                      'bhphotovideo','biblegateway','bizjournals','bleacherreport','blogger','blogspot','bloomberg',
                      'bongacams','booking','breitbart','britishgas','businessinsider','buzzfeed','capitalone',
                      'capitalone360','cargurus','cbslocal','cbsnews','cbssports','chaturbate','chevron',
                      'chicagotribune','citibankonline','comcast','comenity','concursolutions','conservativetribune',
                      'costco','craigslist','creditkarma','crooksandliars','crunchyroll','custhelp','dailykos',
                      'dailymail','dailymotion','darpa','delta','democraticunderground','deviantart',
                      'dickssportinggoods','diply','discovercard','disney','diynetwork','docusign','donaldjtrump',
                      'dropbox','drudgereport','duckduckgo','duke-energy','ebates','edfenergy','eventbrite',
                      'eversource','expedia','exxonmobil','facebook','fbcdn','fedex','feedly','fidelity',
                      'firstenergycorp','fitbit','fivethirtyeight','flickr','forbes','foxnews','gamepedia','gamestop',
                      'gawker','geico','gfycat','giphy','github','gizmodo','godaddy','gofundme','goodhousekeeping',
                      'google','groupon','halliburton','harvard','hbogo','hbonow','hclips','hilton','homedepot',
                      'hotnewhiphop','houzz','howtogeek','huffingtonpost','humblebundle','icims','icloud','imgur',
                      'indiatimes','infusionsoft','instagram','instructables','instructure','investopedia','jalopnik',
                      'jcpenney','jezebel','kaiserpermanente','khanacademy','kickstarter','kinja','kissanime','kohls',
                      'kotaku','latimes','lifebuzz','lifehacker','linkedin','livejasmin','lowes','mariott','mashable',
                      'mayoclinic','microsoft','motherjones','mozilla','myfitnesspal','naver','nbcnews','nbcsports',
                      'netflix','newegg','nexusmods','nordstrom','norton','nymag','nypost','nytimes','officedepot',
                      'okcupid','onclickads','outbrain','overstock','ozock','papajohns','patheos','paypal',
                      'photobucket','pinterest','pixnet','pizzahut','politico','popads','pornhub','progress-energy',
                      'putlocker','qualtrics','quizlet','quora','realclearpolitics','realtor','reddit','redfin',
                      'redtube','retailmenot','reuters','roblox','salesforce','samsclub','samsung','schneider-electric',
                      'schwab','searchincognito','sears','sephora','sfgate','shopify','shutterfly','shutterstock',
                      'signupgenius','skype','slickdeals','slideshare','smugmug','solarcity','soundcloud','southwest',
                      'spotify','stackexchange','stackoverflow','stanford','staples','starbucks','stubhub','suntrust',
                      'surveymonkey','swagbucks','taboola','talkingpointsmemo','tdbank','thameswater','thedailybeast',
                      'theguardian','thekitchn','thepennyhoarder','thepiratebay','ticketmaster','timewarnercable',
                      'tomshardware','toysrus','travelocity','trello','tripadvisor','trulia','tumblr','twitch',
                      'twitter','upornia','upstreamonline','urbandictionary','usatoday','verizon','victoriassecret',
                      'vimeo','w3schools','walgreens','walmart','washingtonpost','wayfair','webex','webmd','weebly',
                      'wellsfargo','whatsapp','wikia','wikihow','wikimedia','wikipedia','wittyfeed','wordpress',
                      'wunderground','xfinity','xhamster','xvideos','yahoo','youporn','youtube','zappos','zillow',
                      'zulily']

        eval_metrics['tm'] = 0

        for tm in trademarks:
            if tm in response.url:
                eval_metrics['tm'] = 1

        # WHOIS
        iswho = whois.whois(response.url)
        current_date = datetime.datetime.now()

        eval_metrics['creation'] = -1
        eval_metrics['update'] = -1
        eval_metrics['expiration'] = -1

        try:
            creation = iswho.creation_date
            print("Creation date: " + str(creation))
            if type(creation) == list:
                eval_metrics['creation'] = (current_date - creation[0]).days
                print("List: " + str(eval_metrics['creation']))
            else:
                eval_metrics['creation'] = (current_date - creation).days
                print("Not list: " + str(eval_metrics['creation']))
        except:
            print("Error!!! Creation date not found!!!")

        try:
            update = iswho.updated_date
            print("Update: " + str(update))
            if type(update) == list:
                eval_metrics['update'] = (current_date - update[0]).days
            else:
                eval_metrics['update'] = (current_date - update).days
        except:
            print("Error!!!Update not found!!!")

        try:
            expiration = iswho.expiration_date
            if type(expiration) == list:
                eval_metrics['expiration'] = (expiration[0] - current_date).days
            else:
                eval_metrics['expiration'] = (expiration - current_date).days
        except:
            pass


        # Webpage title
        metadata['title'] = response.css('title::text').getall()

        # Favicon
        metadata['favicon'] = []
        eval_metrics['ext_favicon'] = 0
        links = response.css('link')

        for link in links:
            try:
                if 'icon' in link.attrib['rel']:
                    URLfavicon = link.attrib['href']
                    metadata['favicon'].append(URLfavicon)
                    if urlparse(URLfavicon).netloc != urlparse(response.url).netloc and urlparse(URLfavicon).netloc != '':
                        eval_metrics['ext_favicon'] = 1
            except:
                pass

        if len(metadata['favicon']) == 0:
            eval_metrics['ext_favicon'] = -1

        # <a> tags
        metadata['links'] = response.css('a::attr(href)').getall()

        eval_metrics['num_links'] = 0
        eval_metrics['link_len'] = 0
        eval_metrics['shortener'] = 0
        eval_metrics['double_slash'] = 0
        eval_metrics['link_https'] = 0

        shorteners = ['is.gd', 'soo.gd', 's2r.co', 'clicky.me', 'goo.gl', 'bit.ly', 'tinyurl.com', 'tiny.cc', 'lc.chat', 
                      'budurl.com']

        for UrlLink in metadata['links']:
            eval_metrics['num_links'] += 1
            eval_metrics['link_len'] += len(UrlLink)
            for short_url in shorteners:
                if short_url in UrlLink.lower():
                    eval_metrics['shortener'] += 1
            if UrlLink.count('//') > 1:
                eval_metrics['double_slash'] += 1
            if UrlLink.startswith('https'):
                eval_metrics['link_https'] += 1

        if eval_metrics['num_links'] != 0:
            eval_metrics['link_len'] = eval_metrics['link_len'] / eval_metrics['num_links']


        # Image
        metadata['images'] = []

        images = response.css('img')

        int_images = 0
        ext_images = 0
        for iimag in images:
            imageDict = dict()
            try:
                ssource = iimag.attrib['src']
                imageDict['src'] = ssource
                if urlparse(ssource).netloc != urlparse(response.url).netloc and urlparse(ssource).netloc != '':
                    ext_images += 1
                else:
                    int_images += 1
            except:
                imageDict['src'] = None
            try:
                imageDict['alt'] = iimag.attrib['alt']
            except:
                imageDict['alt'] = None
            metadata['images'].append(imageDict)

        if int_images + ext_images > 0:
            eval_metrics['ext_images'] = ext_images / (ext_images + int_images)
        else:
            eval_metrics['ext_images'] = 0

        eval_metrics['num_images'] = int_images + ext_images


        # Save as CSV
        with open(savepath_Clfeval, 'ab') as f:
            print('Saving the output in csn format!')
            # Add header to beginning of file
            if f.tell() == 0:
                f.write('phishing,tagret_url_len,favicon_match,target_url_https,trademark_in_target_url,'
                        'days_since_creation,days_since_update,days_until_expiration,number_of_links,average_link_len,'
                        'num_shortened_links,num_redirect_links,num_https_links,num_images,num_external_images\n')
            # Add data for current website
            f.write('-1,')   # Negative Class -> Benign
            f.write(str(eval_metrics['link_len']) + ',')
            f.write(str(eval_metrics['shortener']) + ',')
            f.write(str(eval_metrics['double_slash']) + ',')
            f.write(str(eval_metrics['link_https']) + ',')
            f.write(str(eval_metrics['num_images']) + ',')
            f.write(str(eval_metrics['ext_images']) + '\n')
            f.write(str(eval_metrics['url_chars']) + ',')
            f.write(str(eval_metrics['ext_favicon']) + ',')
            f.write(str(eval_metrics['root_https']) + ',')
            f.write(str(eval_metrics['tm']) + ',')
            f.write(str(eval_metrics['creation']) + ',')
            f.write(str(eval_metrics['update']) + ',')
            f.write(str(eval_metrics['expiration']) + ',')
            f.write(str(eval_metrics['num_links']) + ',')
            

        self.log('Output saved in csn format.')

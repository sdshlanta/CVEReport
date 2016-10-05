import json
import urllib2
from pprint import PrettyPrinter as prp
from datetime import datetime

pp = prp(indent=4)

class CVESearch(object):

	def __init__(self, base_url='https://cve.circl.lu/api/'):
		self.base_url = base_url
		self.opener = urllib2.build_opener()
		self.opener.addheaders.append(('Content-Type', 'application/json'))
		self.opener.addheaders.append(('User-agent', 'ares - python wrapper around cve.circl.lu (github.com/mrsmn/ares)'))
	
	def __urljoin(self, *args):
		""" Internal urljoin function because urlparse.urljoin sucks. """
		
		return "/".join(map(lambda x: str(x).rstrip('/'), args))

	def browse(self, query=None):
		url = self.__urljoin(self.base_url, 'browse/')
		if query == None:
			response = self.opener.open(url).read()
			return response
		else:
			response_url = self.__urljoin(url, query)
			response = self.opener.open(response_url).read()
			return response

	def search(self, query):
		url = self.__urljoin(self.base_url, 'search/')
		response_url = self.__urljoin(url, query)
		response = self.opener.open(response_url).read()
		return response

	def id(self, query):
		url = self.__urljoin(self.base_url, 'cve/')
		response_url = self.__urljoin(url, query)
		response = self.opener.open(response_url).read()
		return response

	def last(self):
		url = self.__urljoin(self.base_url, 'last/')
		response = self.opener.open(url).read()
		return response

	def cpe22(self, query):
		url = self.__urljoin(self.base_url, 'cpe2.2/')
		response_url = self.__urljoin(url, query)
		response = self.opener.open(response_url).read()
		return response

	def cpe23(self, query):
		url = self.__urljoin(self.base_url, 'cpe2.3/')
		response_url = self.__urljoin(url, query)
		response = self.opener.open(response_url).read()
		return response

	def cvefor(self, query):
		url = self.__urljoin(self.base_url, 'cvefor/')
		response_url = self.__urljoin(url, query)
		response = self.opener.open(response_url).read()
		return response

c = CVESearch()

def respond(text=None, ssml=None, attributes=None, reprompt_text=None,
			reprompt_ssml=None, end_session=True):
	""" Build a dict containing a valid response to an Alexa request.

	If speech output is desired, either of `text` or `ssml` should
	be specified.

	:param text: Plain text speech output to be said by Alexa device.
	:param ssml: Speech output in SSML form.
	:param attributes: Dictionary of attributes to store in the session.
	:param end_session: Should the session be terminated after this response?
	:param reprompt_text, reprompt_ssml: Works the same as
		`text`/`ssml`, but instead sets the reprompting speech output.
	"""

	obj = {
		'version': '1.0',
		'shouldEndSession': end_session,
		'response': {
			'outputSpeech': {'type': 'PlainText', 'text': ''}
		},
		'sessionAttributes': attributes or {}
	}

	if text:
		obj['response']['outputSpeech'] = {'type': 'PlainText', 'text': text}
	elif ssml:
		obj['response']['outputSpeech'] = {'type': 'SSML', 'ssml': ssml}

	reprompt_output = None
	if reprompt_text:
		reprompt_output = {'type': 'PlainText', 'text': reprompt_text}
	elif reprompt_ssml:
		reprompt_output = {'type': 'SSML', 'ssml': reprompt_ssml}

	if reprompt_output:
		obj['response']['reprompt'] = {'outputSpeech': reprompt_output}

	return obj

		
def getTodaysCVEs(slots, session):
	session_attributes = {}
	mostRecent = json.loads(c.last())[u'results']
	tn = datetime.today().day
	cveToday = []
	for cve in mostRecent:
		datePublished = cve[u'Published']
		t1 = datetime.strptime(datePublished[:datePublished.index('T')],'%Y-%m-%d').day
		if t1 == tn:
			cveToday.append(cve[u'id'])
	numToday = len(cveToday)
	if numToday == 0:
		return respond("No CVEs have been released so far today")
	elif numToday == 1:
		return respond("Only one CVE has been released so far today: %s" % cveToday[0])
	else:
		speechOutput = "The following %d CVEs were released today: " % numToday
		for cve in cveToday:
			speechOutput += "%s " % cve
		return respond(speechOutput)

def getCVE(slots, session):
	CVE = ''
	cveInfo = {}
	try:
		CVE = 'CVE-%d-%d' % (int(slots[u'CVENumberFirstHalf']), int(slots[u'CVENumberSecondHalf']))
		cveInfo = json.loads(c.id(CVE))
	except Exception as e:
			print(e)
			return respond("Something whent horibly wrong and I can't awnser the question.  Perhaps my datasource is down.")
	if len(cveInfo)>0:
		return respond(u"Here is what I know about %s: %s" % (CVE, cveInfo[u'summary']))
	else:
		return respond(u"It appears that CVE doesn't exist, perhaps I misheard you, were you looking for %s?" % CVE)



def on_launch():
	return getTodaysCVEs({}, {})

def on_session_ended():
	pass

def on_session_started(session_started_request, session):
	#print("on_session_started requestId=" + session_started_request['requestId'] + ", sessionId=" + session['sessionId'])
	pass

def on_intent(intent_request, session):
	intents = {
		u"GetCVE":getCVE,
		u"GetTodaysCVEs":getTodaysCVEs,
		u"GetCVEsByDate":getCVEByDate
	}

	print("on_intent requestId=" + intent_request['requestId'] + ", sessionId=" + session['sessionId'])
	intent = intent_request['intent']['name']
	slots = {}
	if 'slots' in intent_request['intent']:
		slots = intent_request['intent']['slots']
		for slot in slots.keys():
			slots[slot] = slots[slot][u'value']
	return intents[intent](slots, session)

def lambda_handler(event, context):
	""" Route the incoming request based on type (LaunchRequest, IntentRequest,
	etc.) The JSON body of the request is provided in the event parameter.
	"""
	print("event.session.application.applicationId=" +
		  event['session']['application']['applicationId'])

	"""
	Uncomment this if statement and populate with your skill's application ID to
	prevent someone else from configuring a skill that sends requests to this
	function.
	"""
	# if (event['session']['application']['applicationId'] !=
	#         "amzn1.echo-sdk-ams.app.[unique-value-here]"):
	#     raise ValueError("Invalid Application ID")

	if event['session']['new']:
		on_session_started({'requestId': event['request']['requestId']}, event['session'])
	if event['request']['type'] == "LaunchRequest":
		return on_launch(event['request'], event['session'])
	elif event['request']['type'] == "IntentRequest":
		return on_intent(event['request'], event['session'])
	elif event['request']['type'] == "SessionEndedRequest":
		return on_session_ended(event['request'], event['session'])
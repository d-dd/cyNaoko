#!/usr/bin/env python

import json
import logging
import subprocess
import time
import re
import urllib2

from ssl import SSLError
from urllib import urlencode, urlopen
from httplib import HTTPConnection, HTTPSConnection

from settings import *

# Throttle all the public methods
# Since there is only one thread which calls API methods this won't be circumvented
# This throttles functions independently, which should be fine
class throttle(object):
    def __init__ (self):
        self.last_call = 0

    def __call__ (self, fn):
        def wrapped(apiclient, *args, **kwargs):
            remaining = API_THROTTLE - time.time() + self.last_call
            if remaining > 0:
                time.sleep(remaining)
            self.last_call = time.time()
            return fn(apiclient, *args, **kwargs)
        return wrapped
    
# A client for all the various APIs used by Naoko
# Responsible for making requests and returning responses
class APIClient(object):
    def __init__(self, keys):
        self.logger = logging.getLogger("apiclient")
        self.logger.setLevel(LOG_LEVEL)
        self.logger.debug("Initializing APIClient")
        self.keys = keys
        self.lastInfo = time.time() - API_THROTTLE
   
    @throttle()
    def getVideoInfo(self, site, vid):
        if site == "yt":
            return self._getYoutubeVideoInfo(vid)
        elif site == "bt":
            return self._getBliptvVideoInfo(vid)
        elif site == "sc":
            return self._getSoundcloudVideoInfo(vid)
        elif site == "vm":
            return self._getVimeoVideoInfo(vid)
        elif site == "dm":
            return self._getDailymotionVideoInfo(vid)
        else:
            return "Unknown"

    # Translates text from src to dst.
    # If src is None the Microsoft Translator will attempt to guess the language.
    # Returns -1 if there's no id or secret to use to get an access token.
    @throttle()
    def translate(self, text, src, dst):
        if not self.keys.mst_id or not self.keys.mst_secret: return -1
        token = self._getMSTAccessToken()
        if not token: return ""
        out = (self._MSTranslate(token, text, src, dst) or "").decode("utf-8")
        # Highly unlikely that any valid translation contains the following
        if out.find("<h1>Argument Exception</h1>") != -1: return ""
        # Seems to error if too many requests are made in a short interval
        if out.find("<h1>TranslateApiException</h1>") != -1: return ""
        return out[out.find(">") + 1:out.rfind("<")]

    def _MSTranslate(self, token, text, src, dst):
        self.logger.debug("Attempting to translate %r from %s to %s" % (text, src, dst))
        con = HTTPConnection("api.microsofttranslator.com", timeout=10)
        params = {  "appId"         : "Bearer " + token,
                    "text"          : text.encode("utf-8"),
                    "to"            : dst.encode("utf-8"),
                    "contentType"   : "text/plain"}
        if src:
            params["from"] = src.encode("utf-8")
        out = None
        try:
            con.request("GET", "/V2/Http.svc/Translate?%s" % (urlencode(params)))
            out = con.getresponse().read()
        except Exception as e:
            self.logger.warning("Translation failed.")
            self.logger.debug(e)
        finally:
            con.close()
            return out

    # Get the temporary access token for Microsoft Translate using the provided client id and secret.
    def _getMSTAccessToken(self):
        self.logger.debug("Retrieving Microsoft Translate access token.")
        con = HTTPSConnection("datamarket.accesscontrol.windows.net", timeout=10)
        body = {"client_id"         : self.keys.mst_id,
                "client_secret"     : self.keys.mst_secret,
                "grant_type"        : "client_credentials",       
                "scope"             : "http://api.microsofttranslator.com"}
        accessToken = None
        try:
            con.request("POST", "/v2/OAuth2-13", urlencode(body))
            accessToken = json.loads(con.getresponse().read())["access_token"]
        except Exception as e:
            self.logger.warning("Failed to retrieve a valid access token.")
            self.logger.debug(e)
        finally:
            con.close()
            return accessToken

    # Query the Wolfram Alpha API.
    @throttle()
    def wolfram(self, text):
        if not self.keys.wf_id: return -1
        data = self._getWolframAPI(text)
        if type(data) is str or type(data) is unicode:
            if data.find("success='true'", 0, data.find("<pod ")) != -1:
                startTag = "<plaintext>"
                endTag = "</plaintext>"
                # Try to find a primary pod.
                # If there is no primary pod pick the first pod after the input pod.
                startIndex = data.find("primary='true'")
                if startIndex == -1:
                    startIndex = data.find("id='Input'")
                    startIndex = data.find("<pod ", startIndex)
            
                if startIndex == -1:
                    return None

                return " ".join(data[data.find(startTag, startIndex) + len(startTag):data.find(endTag, startIndex)].split()).replace("|","/")
        return None

    def _getWolframAPI(self, text):
        self.logger.debug("Querying Wolfram with %r" % (text))
        # Wolfram Alpha can be fairly slow so a more generous timeout is used.
        con = HTTPConnection("api.wolframalpha.com", timeout=20)
        params = {"appid"   : self.keys.wf_id,
                  "units"   : "metric",
                  "format"  : "plaintext",
                  "input"   : text.encode("utf-8")}
        data = None
        try:
            con.request("GET", "/v2/query?%s" % (urlencode(params)))
            data = con.getresponse().read().decode("utf-8")
        except Exception as e:
            self.logger.warning("Failed to retrieve a valid response from the Wolfram Alpha API.")
            self.logger.debug(e)
        finally:
            con.close()
            return data

    @throttle()
    def anagram(self, text):
        data = self._getAnagram(text)
        if type(data) is str or type(data) is unicode:
            if "Your text was too short.  We recommend 7-30 letters." in data:
                return -1
            m = re.match(r".*<span class=\"black-18\">'(.*)'</span>", data, re.DOTALL)
            if m:
                return m.groups()[0]
        return None

    def _getAnagram(self, text):
        con = HTTPConnection("anagramgenius.com", timeout=20)
        params = {"source_text"   : text.encode("utf-8")}
        data = None
        try:
            con.request("GET", "/server.php?%s" % (urlencode(params)))
            data = con.getresponse().read().decode("utf-8")
        except Exception as e:
            self.logger.warning("Failed to retrieve a valid response from the anagram server.")
            self.logger.debug(e)
        finally:
            con.close()
            return data

    # Resolve a Soundcloud URL into usable track information.
    # Soundcloud is the only site that does not include the ids in their URLs.
    @throttle()
    def resolveSoundcloud(self, url):
        if not self.keys.sc_id: return False
        self.logger.debug("Resolving URL using the Soundcloud API.")
        data = self._resolveSoundcloudAPI(url)
        if isinstance(data, dict) and not "errors" in data:
            if "location" in data:
                return self._getSoundcloudID(data["location"])
        return False

    # The call to the API is necessary to make sure it's a track and not a stream
    def _getSoundcloudID(self, url):
        data = None
        try:
            resp = json.loads(urlopen(url).read())
            if resp["kind"] == "track":
                data = resp["id"]
        except Exception as e:
            # Many things can go wrong with an HTTP request or during JSON parsing
            self.logger.warning("Error retrieving Soundcloud API information.")
            self.logger.debug(e)
        finally:
            return data

    def _resolveSoundcloudAPI(self, url):
        con = HTTPSConnection("api.soundcloud.com", timeout=10)
        params = {"client_id" : self.keys.sc_id,
                  "url"       : url}
        data = None
        try:
            con.request("GET", "/resolve.json?%s" % (urlencode(params)))
            data = json.loads(con.getresponse().read())
        except Exception as e:
            # Many things can go wrong with an HTTP request or during JSON parsing
            self.logger.warning("Error retrieving Soundcloud API information.")
            self.logger.debug(e)
        finally:
            con.close()
            return data

    @throttle()
    def getSoundcloudURL(self, id):
        if not self.keys.sc_id: return False
        con = HTTPSConnection("api.soundcloud.com", timeout=10)
        params = {"client_id" : self.keys.sc_id}
        data = None
        try:
            con.request("GET", "/tracks/%s.json?%s" % (id, urlencode(params)))
            resp = json.loads(con.getresponse().read())
            if resp["kind"] == "track":
                data = resp["permalink_url"]
        except Exception as e:
            # Many things can go wrong with an HTTP request or during JSON parsing
            self.logger.warning("Error retrieving Soundcloud API information.")
            self.logger.debug(e)
        finally:
            return data

    # Get information on videos from various video APIs.
    # Take in video ids, and return a tuple containing the title, duration, and whether embedding is allowed.
    # Return False when a video is invalid or the API response is malformed.

    def _getYoutubeVideoInfo(self, vid):
        data = self._getYoutubeAPI(vid) 
        if isinstance(data, dict) and not "error" in data:
            try:
                data = data["data"]
                allowed = data["accessControl"]["embed"] == "allowed"
                if "restrictions" in data:
                    for r in data["restrictions"]:
                        if r["type"] == "country" and r["relationship"] == "deny":
                            allowed = allowed and not (REQUIRED_COUNTRIES & set(r["countries"].split(" ")))

                return (data["title"], data["duration"], allowed)
            except (TypeError, ValueError, KeyError) as e:
                # Improperly formed Youtube API response
                print e
                self.logger.warning("Invalid Youtube API response.")
        elif data == "Unknown": return data
        elif isinstance(data, dict) and "message" in data["error"] and data["error"]["message"] == "Service Unavailable": return "Unknown"
        # private, deleted, and invalid videos
        elif isinstance(data, dict) and "errors" in data["error"]: return False
        # When Youtube returns something else
        else:
            self.logger.warning("Invalid/malformed Youtbe API response.")
            return "Unknown"

    def _getYoutubeAPI(self, vid):
        self.logger.debug("Retrieving video information from the Youtube API.")
        con = HTTPSConnection("gdata.youtube.com", timeout=10)
        params = {"v": 2, "alt": "jsonc", "key": self.keys.yt_id}
        data = None
        try:
            con.request("GET", "/feeds/api/videos/%s?%s" % (vid, urlencode(params)))
            data = json.loads(con.getresponse().read())
        except Exception as e:
            # Many things can go wrong with an HTTP request or during JSON parsing
            self.logger.warning("Error retrieving Youtube API information.")
            self.logger.debug(e)
            # Treat a communication failure as Unknown and assume the video will play
            # The video will not be recorded or flagged as invalid
            # -- TODO -- Possibly treat other API failures as unknown. Youtube is the most common and I have not 
            # looked at the other APIs as much.
            data = "Unknown"
        finally:
            con.close()
            return data

    def _getDailymotionVideoInfo(self, vid):
        data = self._getDailymotionAPI(vid) 
        if isinstance(data, dict) and not "error" in data:
            try:
                return (data["title"], data["duration"], data["allow_embed"])
            except (TypeError, ValueError, KeyError) as e:
                self.logger.warning("Invalid Dailymotion API response.")
        # If both the initial request and the curl fallback failed, treat the video as unknown. 
        if data == "SSL Failure":
            return "Unknown"
        return False

    def _getDailymotionAPI(self, vid):
        self.logger.debug("Retrieving video information from the Dailymotion API.")
        con = HTTPSConnection("api.dailymotion.com", timeout=10)
        params = {"fields", "title,duration,allow_embed"}
        data = None
        try:
            try:
                con.request("GET", "/video/%s?fields=title,duration,allow_embed" % (vid))
                data = con.getresponse().read()
            except SSLError as e:
                # There is a bug in OpenSSL 1.0.1 which affects Python 2.7 on systems that rely on it.
                # Attempt to use curl as a fallback.
                # Curl must be installed for this to work.
                # This is the worst hack I have ever coded.
                # Since vid is a valid video id there is no risk of any attack.
                self.logger.warning("SSL Error, attempting to use curl as a fallback.")
                try:
                    data = subprocess.check_output(["curl", "-k", "-s", "-m 10",
                        "https://api.dailymotion.com/video/%s?fields=title,duration,allow_embed" % (vid)])
                except Exception as e:
                    self.logger.warning("Curl fallback failed.")
                    data = "SSL Failure"
                    raise e
            # Do this last and separately to avoid catching it elsewhere.
            data = json.loads(data)
        except Exception as e:
            # Many things can go wrong with an HTTP request or during JSON parsing
            self.logger.warning("Error retrieving Dailymotion API information.")
            self.logger.debug(e)
        finally:
            con.close()
            return data

    def _getSoundcloudVideoInfo(self, vid):
        if not self.keys.sc_id: return "Unknown"
        data = self._getSoundcloudAPI(vid)
        if isinstance(data, dict):
            try:
                if not "errors" in data:
                    return (data["title"], data["duration"]/1000.0, data["sharing"] == "public")
                elif json.dumps(data, encoding="utf-8").find("401 - Unauthorized") != -1:
                    return "Unknown"
            except (TypeError, ValueError, KeyError, UnicodeDecodeError) as e:
                self.logger.warning("Invalid Soundcloud API response.")
        return False

    def _getSoundcloudAPI(self, vid):
        self.logger.debug("Retrieving track information from the Soundcloud API.")
        con = HTTPSConnection("api.soundcloud.com", timeout=10)
        params = {"client_id" : self.keys.sc_id}
        data = None
        try:
            con.request("GET", "/tracks/%s.json?%s" % (vid, urlencode(params)))
            data = json.loads(con.getresponse().read())
        except Exception as e:
            # Many things can go wrong with an HTTP request or during JSON parsing
            self.logger.warning("Error retrieving Soundcloud API information.")
            self.logger.debug(e)
        finally:
            con.close()
            return data

    def _getVimeoVideoInfo(self, vid):
        data = self._getVimeoAPI(vid)
        if isinstance(data, list):
            try:
                data = data[0]
                return (data["title"], data["duration"], data["embed_privacy"] == "anywhere")
            except (TypeError, ValueError, KeyError) as e:
                self.logger.warning("Invalid Vimeo API response.")
        return False

    def _getVimeoAPI(self, vid):
        self.logger.debug("Retrieving video information from the Vimeo API.")
        con = HTTPConnection("vimeo.com")
        data = None
        try:
            con.request("GET", "/api/v2/video/%s.json" % (vid))
            data = json.loads(con.getresponse().read())
        except Exception as e:
            # Many things can go wrong with an HTTP request or during JSON parsing
            self.logger.warning("Error retrieving Vimeo API information.")
            self.logger.debug(e)
        finally:
            con.close()
            return data

    def _getBliptvVideoInfo(self, vid):
        data = self._getBliptvAPI(vid)
        if isinstance(data, dict) and not "error" in data:
            try:
                data = data["Post"]
                return (data["title"], int(data["media"]["duration"]), data["hidden"] == "0")
            except (TypeError, ValueError, KeyError) as e:
                # Improperly formed Blip.tv API response
                self.logger.warning("Invalid Blip.tv API response.")
        return False

    def _getBliptvAPI(self, vid):
        self.logger.debug("Retrieving video information from the Blip.tv API.")
        con = HTTPConnection("blip.tv", timeout = 10)
        params = {"version" : 2, "skin" : "json"}
        data = None
        try:
            con.request("GET", "/posts/%s?%s" % (vid, urlencode(params)))
            data = con.getresponse().read()
            data = data[data.find("[") + 1:data.rfind("]")]
            data = json.loads(data)
        except Exception as e:
            self.logger.warning("Error retrieving Blip.tv API information.")
            self.logger.debug(e)
        finally:
            con.close()
            return data

    def getVocaDbApi(self, service, vidId):
         """Returns vocadb id and data to the main thread"""
         if service not in ("yt", "vm"): # only Youtube and Vimeo for now
             return None, None
         # First, call VocaDB API by Youtube ID
         if service == "yt":
             vocadb_id, vocadb_data = self._getVocaDbApi("YouTube", vidId)
             if vocadb_id:
                 self.logger.info("Successfully obtained API via Youtube ID.")
                 return vocadb_id, vocadb_data

         # if Youtube ID lookup fails, parse Youtube description for smid
         nicoId = self._getNicoId(service, vidId)
         if nicoId:
             self.logger.debug("Requesting API with Nico ID")
             vocadb_id, vocadb_data = self._getVocaDbApi("NicoNicoDouga", nicoId)
             return vocadb_id, vocadb_data
         return None, None

    def _getVocaDbApi(self, service, vidId):
        url = ["http://vocadb.net/api/songs"]
        opts = "&lang=romaji&fields=artists,names"
        url.extend(["?pvId=", vidId, "&pvService=", service, opts])
        url = ''.join(url)
        vdbJson = self._getJsonApi(url, "VocaDB")
        return self._verifyVdbJson(vdbJson)

    def _getVocaDbApiVersionOne(self, service, vidId):
        url = ["http://vocadb.net/Api/v1/Song/ByPV"]
        opts = "&lang=romaji&IncludeAlbums=False&includeTags=False"
        url.extend(["?pvID=", vidId, "&service=", service, opts])
        url = ''.join(url)
        self.logger.debug("VDB API: Requesting data from VocaDB: %s" % url)
        vdbJson = self._getJsonApi(url, "VocaDB")
        return self._verifyVdbJson(vdbJson)

    def _verifyVdbJson(self, vdbJson):
        try:
            vdbDict = json.loads(vdbJson)
        except TypeError, e:
            self.logger.error("Could not decode JSON:%s" % e)
            return None, None
        try:
            return vdbDict["id"], vdbJson # lowercase, version 2 VocaDB Api
        except (TypeError, KeyError) as e:
            self.logger.error("Could not parse JSON:%s" % e)
            return None, None
        
    def getVdbById(self, service, vidId, vocadb_id, vocadb_rep):
        url = ["http://vocadb.net/api/songs/"]
        options = "?lang=romaji&fields=artists,names"
        url.extend([vocadb_id, options])
        url = ''.join(url)
        self.logger.debug("VOCADB API: Requesting data from VocaDB: %s" % url)
        vdbJson = self._getJsonApi(url, "VocaDB")
        return self._verifyVdbJson(vdbJson)


    def _getNicoId(self, service, vidId):
        if service == "yt":
            url = ''.join(["https://gdata.youtube.com/feeds/api/videos/", vidId,
                   "?v=2&fields=media:group(media:description)&alt=json"])
            jsonDesc = self._getJsonApi(url, "Youtube")
            if jsonDesc:
                try:
                    diDesc = json.loads(jsonDesc)
                    desc = diDesc["entry"]["media$group"]["media$description"]["$t"]
                except (KeyError, TypeError) as e:
                    self.logger.error("Error parsing json: %s" % repr(e))
                    return None
                nicoID = self._parseDesc(desc)
                return nicoID
        if service == "vm":
            url = ["http://vimeo.com/api/v2/video/", vidId, ".json"]
            url = ''.join(url)
            jsonDesc = self._getJsonApi(url, "Vimeo")
            if jsonDesc:
                try:
                    diDesc = json.loads(jsonDesc)
                    desc = diDesc[0]["description"]
                except (KeyError, TypeError) as e:
                    self.logger.error("Error parsing vimeo JSON:%s" % repr(e))
                    return None
                nicoID = self._parseDesc(desc)
                return nicoID

        return None

    def _getJsonApi(self, url, provider):
        self.logger.debug("Obtaining API from %s, %s ." % (provider, url))
        try:
            if provider == "VocaDB":
                req = urllib2.Request(url)
                req.add_header('data', 'JSON')
                req.add_header('User-agent', VDB_USER_AGENT)
                return urllib2.urlopen(req, timeout=5).read()
            else:
                return urllib2.urlopen(urllib2.Request(url), timeout=5).read()
        except urllib2.socket.timeout, e:
            self.logger.error("API Error: %s . %s" % (url, e))
        except urllib2.URLError, e:
            self.logger.error("API Error: %s . %s" % (url, e))
        except urllib2.HTTPError, e:
            self.logger.error("API Error: %s . %s" % (url, e))
        return None

    def _parseDesc(self, desc):
        matchObj = re.search(r"sm[0-9]{6,9}|nm[0-9]{6,9}", desc)
        if matchObj:
            return matchObj.group()
        matchObj = re.search(r"(nicovideo.jp/watch/)(\d{6,12})", desc)
        if matchObj:
            return matchObj.group(2)
        else:
            self.logger.info("_parseDesc: no match found")

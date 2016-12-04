import json
import regex
from SimpleEncryption.Utils import Utils
class Json:
    def CookieToJson(self, rawCookie):
        # rawCookie.map
        cookieParts = regex.split('(?<!\\\)(?:\\\\\\\)*&', rawCookie)#Kill me a hundred times lookbehind shit
        print(cookieParts)
        return(json.loads(json.dumps(dict(map(self.__keyValueParse, cookieParts)), ensure_ascii=False)))


    def __keyValueParse(cookie):
        keyValueCookie = regex.split("(?<!\\\)(?:\\\\\\\)*=", cookie)
        if (len(keyValueCookie) != 2):
            raise ValueError("Cookie was not <key>=<value>")
        return[keyValueCookie[0], keyValueCookie[1]]

    def __keyValueCreate(items):
        return(items[0] + "=" + str(items[1]))

    def jsonToCookie(self, jsonData):
        return("&".join(list(map(self.__keyValueCreate, jsonData.items()))))

    def createJsonProfile(self, email):
        return json.loads(json.dumps({"email": Utils.sanitizeInput(Utils, email), "uid": "10", "role": "user"}))

    def createProfile(self, email):
        return self.jsonToCookie(self, self.createJsonProfile(self, email))



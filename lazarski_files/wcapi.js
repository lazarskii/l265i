(function () {
	if (!window.$WC) {
		window.$WC = {};
	}

  base64.polyfill(window);

	var util = {};

  function validateEmail(email) {
    return /^(([^<>()[\]\\.,;:\s@\"]+(\.[^<>()[\]\\.,;:\s@\"]+)*)|(\"[^\"\\]+\"))@((\[(25[0-5]|2[0-4]\d|[0-1]?\d?\d)(\.(25[0-5]|2[0-4]\d|[0-1]?\d?\d)){3}\])|(([a-zA-Z\-0-9]+\.)+[a-zA-Z]{2,}))$/i.test(
      email
    );
  };

  function bufferToBase64(buffer) {
    const byteView = new Uint8Array(buffer);
    let str = "";
    for (const charCode of byteView) {
      str += String.fromCharCode(charCode);
    }
    return base64.byteEncode(str);
  }

  function base64urlToBase64String(base64urlString) {
    const padding = "==".slice(0, (4 - base64urlString.length % 4) % 4);
    return base64urlString.replace(/-/g, "+").replace(/_/g, "/") + padding;
  }

  function base64ToBuffer(base64String) {
    const str = base64.decode(base64String);
    const buffer = new ArrayBuffer(str.length);
    const byteView = new Uint8Array(buffer);
    for (let i = 0; i < str.length; i++) {
      byteView[i] = str.charCodeAt(i);
    }
    return buffer;
  }

  (function () {
    function utf8Encode(str) {
      return unescape(encodeURI(str));
    } /// Decode UTF-8 string to multi-byte string

    function mbEncode(data) {
      if (!data) return data;
      return btoa(utf8Encode(data));
    } // Decodes to multi-byte string if utf8-encoded

    function mbDecode(data) {
      let ret = data;
      if (ret) {
        ret = atob(String(ret).replace(/_/g, '/').replace(/-/g, '+'));
      }

      try {
        ret = decodeURIComponent(escape(ret));
      } catch (ex) { }
      return ret;
    }

    util.base64Encode = mbEncode;
    util.base64ByteEncode = window.btoa;
    util.base64Decode = mbDecode;
  }());

  (function () {
    function Event(name, id, func) {
      this.name = name;
      this.id = id;
      this.func = func;
    }

    function Emitter() {
      var events = [];

      const getEventIndex = function (name, id) {
        let i = events.length;
        while (i--) {
          if (events[i].name === name && events[i].id === id) {
            return i;
          }
        }

        return -1;
      };

      const getEvents = function (name) {
        var evs = [];
        for (let i = 0, iMax = events.length; i < iMax; i++) {
          if (events[i].name === name) {
            evs.push(events[i]);
          }
        }

        return evs;
      };

      this.register = function (name, id, func) {
        if (!name) {
          return;
        }

        var idx = getEventIndex(name, id);
        var ev = new Event(name, id, func);
        if (idx === -1) {
          events.push(ev);
        } else {
          events[idx] = ev;
        }
      };

      this.on = this.register;

      this.unregister = function (name, id) {
        if (!name) {
          return;
        }

        if (id) {
          let idx = getEventIndex(name, id);
          if (idx !== -1) {
            events.splice(idx, 1);
          }
        }
        else {
          let i = events.length;
          while (i--) {
            if (events[i].name === name) {
              events.splice(i, 1);
            }
          }
        }
      };

      this.off = this.unregister;

      this.offAll = function (id) {
        let i = events.length;
        while (i--) {
          if (events[i].id === id) {
            events.splice(i, 1);
          }
        }
      };

      this.trigger = function (name, data) {

        let evs = getEvents(name);
        for (let i = 0, iMax = evs.length; i < iMax; i++) {
          evs[i].func(data, name);
        }
      };

      this.emit = this.trigger;

      this.propagate = function (data, name) {
        this.trigger(name, data);
      };

      this.isRegistered = function (name, id) {
        let i = events.length;
        while (i--) {
          if (events[i].id === id && events[i].name === name) {
            return true;
          }
        }

        return false;
      };
    }

    util.Emitter = Emitter;
  }());

  (function () {
    function CredentialsService() {
      var self = this;
      Object.assign(this, new util.Emitter());

      let available = !!window.PublicKeyCredential;
      this.isAvailable = function () {
        return available;
      };

      if (!available) {
        return;
      }

      this.deviceRegistrationAlreadyOffered = function () {
        return $WC && $WC.settings && $WC.settings.getBool("WebAuthnDeviceRegistrationOffered");
      };

      this.offerDeviceRegistration = function () {
        if ($WC && $WC.settings) {
          $WC.settings.save("WebAuthnDeviceRegistrationOffered", "Yes");
        }
      };

      var _register = function (json, useType) {
        if (!json || !json.response || !(json.response instanceof window.AuthenticatorAttestationResponse)) {
          self.emit("credentials-registration-failure", { error: { response: json, error_message: "Invalid client response." } });
          return new Promise((res, rej) => rej("Invalid client response"));
        }

        var pubKeyCredential = {};
        try {
          pubKeyCredential.authenticatorAttachment = json.authenticatorAttachment;
          pubKeyCredential.type = json.type;
          pubKeyCredential.credentialId = base64urlToBase64String(json.id);
          pubKeyCredential.response = {};
          pubKeyCredential.response.attestationObject = bufferToBase64(json.response.attestationObject);
          pubKeyCredential.response.clientDataJSON = bufferToBase64(json.response.clientDataJSON);
          if (typeof json.getClientExtensionResults === "function") {
            pubKeyCredential.clientExtentionResults = json.getClientExtensionResults();
          }
          if (typeof json.response.getTransports === "function") {
            pubKeyCredential.transports = json.response.getTransports();
          }
        } catch (ex) {
          console.log(ex);
        }

        pubKeyCredential.useType = useType;

        if (json.token) {
          pubKeyCredential.token = json.token;
        }

        var request = $WC.API.post("authenticate/credentials/register", pubKeyCredential);
        return request.then(res => {
          if (!res) {
            self.emit("credentials-registration-failure", { error: { reason: res, error_message: "Invalid server response." } });
            return;
          }

          if (res.error) {
            self.emit("credentials-registration-failure", { error: { reason: res, error_message: "Server responded with an error" } });
            return;
          }

          if (res.success) {
            self.emit("credentials-registration-success", res);
            return res;
          }

        }).fail(function (ex) {
          self.emit("credentials-registration-failure", { error: { reason: ex, error_message: "Client threw an error." } });
        });
      };

      this.register = function (useType, params, authAttachment) {
        useType = useType || "login";
        params = !params ? {} : params;
        params.useType = useType;

        if (useType === "2fa" && !params.current_password && !params.token) {
          self.emit("credentials-registration-failure", { error: { reason: useType, error_message: "Invalid parameter: '2fa'" } });
          return new Promise((res, rej) => rej("Invalid parameters"));
        }
        else if (useType === "login" && !params.current_password) {
          self.emit("credentials-registration-failure", { error: { reason: useType, error_message: "Invalid parameter: 'login'" } });
          return new Promise((res, rej) => rej("Invalid parameters"));
        }

        if (authAttachment) {
          params[authAttachment] = true;
        }

        var request = $WC.API.get("authenticate/credentials/register/challenge", params);
        return request.then(createArgs => {

          if (!createArgs) {
            self.emit("credentials-registration-failure", { error: { reason: createArgs, error_message: "Invalid server response." } });
            return;
          }

          if (createArgs.error) {
            self.emit("credentials-registration-failure", { error: { reason: createArgs, error_message: "Server responded with an error." } });
            return;
          }

          if (createArgs.csrf_token) {
            delete createArgs.csrf_token;
          }
          try {
            createArgs.challenge = base64ToBuffer(createArgs.challenge);
            createArgs.user.id = base64ToBuffer(createArgs.user.id);
            createArgs.excludeCredentials = createArgs.excludeCredentials.map((cred) => {
              cred.id = base64ToBuffer(cred.id);
              return cred;
            });
          } catch (ex) {
            console.log(ex);
            self.emit("credentials-registration-failure", { error: { reason: ex, error_message: "publicKey arguments had invalid properties" } });
            return;
          }

          navigator.credentials.create({ publicKey: createArgs })
            .then(pubKeyCredential => {
              if (!pubKeyCredential || !pubKeyCredential.response || !(pubKeyCredential.response instanceof window.AuthenticatorAttestationResponse)) {
                self.emit("credentials-registration-failure", { error: { reason: pubKeyCredential, error_message: "Invalid client response." } });
                return new Promise((res, rej) => rej("Invalid client response"));
              }

              if (createArgs.token) {
                pubKeyCredential.token = createArgs.token;
              }

              return _register(pubKeyCredential, useType);
            }).catch(function (ex) {
              self.emit("credentials-registration-failure", { error: { reason: ex, error_message: "Client threw an error." } });
            });
        }).fail(function (ex) {
          self.emit("credentials-registration-failure", { error: { reason: ex, error_message: "Server threw an error." } });
        });
      };

      var _authenticate = function (json) {
        if (!json || !json.response || !(json.response instanceof window.AuthenticatorAssertionResponse)) {
          self.emit("credentials-authentication-failure", { error: { reason: json, error_message: "Invalid client response." } });
          return new Promise((res, rej) => rej("Invalid client response"));
        }

        var assertion = {
          authenticatorAttachment: json.authenticatorAttachment,
          credentialId: base64urlToBase64String(json.id),
          response: {
            authenticatorData: bufferToBase64(json.response.authenticatorData),
            clientDataJSON: bufferToBase64(json.response.clientDataJSON),
            signature: bufferToBase64(json.response.signature)
          },
          type: json.type,
          clientExtensionResults: json.getClientExtensionResults(),
          user: json.user,
          lang: json.lang,
          theme: json.theme,
          remember_user: json.remember_user,
          useType: json.useType,
          password_recovery: json.password_recovery,
          token: json.token
        };

        if (json.response.userHandle) {
          assertion.response.userHandle = bufferToBase64(json.response.userHandle);
        }

        var request = $WC.API.post("authenticate/credentials/auth", assertion);
        return request.then(res => {
          if (!res || res.error) {
            self.emit("credentials-authentication-failure", { error: { reason: res, error_message: "Invalid server response." } });
            return;
          }

          res.useType = json.useType;
          self.emit("credentials-authentication-success", res);
          return res;
        }).fail(function (ex) {
          self.emit("credentials-authentication-failure", { error: { reason: ex, error_message: "Server threw an error." } });
        });
      };

      this.authenticate = function (user, lang, theme, remember_user, useType, params) {
        useType = useType || "login";
        params = !params ? {} : params;
        params.user = user;
        params.useType = useType;
        if (useType === "2fa" && !params.token) {
          self.emit("credentials-authentication-failure", { error: { reason: "useType", error_message: "Invalid parameter: '2fa'." } });
          return new Promise((res, rej) => rej("Invalid params"));
        }

        var request = $WC.API.post("authenticate/credentials/auth/challenge", params);
        return request.then(challengeArgs => {
          if (!challengeArgs || challengeArgs.error) {
            self.emit("credentials-authentication-failure", { error: { reason: challengeArgs, error_message: "Invalid server response." } });
            return;
          }

          if (challengeArgs.csrf_token) {
            delete challengeArgs.csrf_token;
          }

          try {
            challengeArgs.challenge = base64ToBuffer(challengeArgs.challenge);
            challengeArgs.allowCredentials = challengeArgs.allowCredentials.map(cred => {
              cred.id = base64ToBuffer(cred.id);
              return cred;
            });
          } catch (ex) {
            self.emit("credentials-authentication-failure", { error: { reason: ex, error_message: "publicKey had invalid properties." } });
            return;
          }

          navigator.credentials.get({ publicKey: challengeArgs })
            .then(assertion => {
              if (!assertion || !assertion.response || !(assertion.response instanceof window.AuthenticatorAssertionResponse)) {
                self.emit("credentials-authentication-failure", { error: { reason: assertion, error_message: "Invalid client response." } });
                return new Promise((res, rej) => rej("Invalid client response"));
              }

              if (!challengeArgs.allowCredentials.some(cred => bufferToBase64(cred.id) === bufferToBase64(assertion.rawId))) {
                self.emit("credentials-authentication-failure", { error: { reason: assertion, error_message: "Invalid client response. Assertion not in list of allowCredentials." } });
                return new Promise((res, rej) => rej("Invalid client response"));
              }

              assertion.user = user;
              assertion.lang = lang;
              assertion.theme = theme;
              assertion.remember_user = remember_user;
              assertion.useType = useType;
              assertion.password_recovery = params.password_recovery || false;
              assertion.token = params.token;

              return _authenticate(assertion);
            }).catch(function (ex) {
              self.emit("credentials-authentication-failure", { error: { reason: ex, error_message: "Client threw an error." } });
            });
        }).fail(function (ex) {
          self.emit("credentials-authentication-failure", { error: { reason: ex, error_message: "Server threw an error." } });
        });
      };

    }

    util.credentialsService = new CredentialsService();
  }());

	(function () {
		function LocalStore() {
      const defL = !!window && window.localStorage;
      var pairs = {};

      this.get = function (key) {
        if (!key) {
          throw new TypeError(
            "Failed to execute 'getItem' on 'Storage': key required."
          );
        }
    
        if (typeof key !== "string") {
          return null;
        }

        if (defL) {
          return window.localStorage.getItem(key);
        }

        return pairs[key] !== undefined ? pairs[key] : null;

      };

      this.set = function (key, value) {
        if (!key) {
          throw new TypeError(
            "Failed to execute 'setItem' on 'Storage': key required."
          );
        } 
    
        if (typeof key !== "string") {
          return;
        }

        pairs[key] = value;

        if (defL) {
          return window.localStorage.setItem(key, value);
        }

   
      };

      this.remove = function (key) {
        if (!key) {
          throw new TypeError(
            "Failed to execute 'removeItem' on 'Storage': key required."
          );
        }

        console.log("removing", key);
        if (typeof key !== "string") {
          return;
        }

        delete pairs[key];

        if (defL) {
          return window.localStorage.removeItem(key);
        }
      };

      this.clear = function () {
        pairs = {};

        if (defL) {
          return window.localStorage.clear();
        }
      };
    }

    function SessionStore() {
      const defS = !!window && window.sessionStorage;
      var self = this;
      var pairs = {};

      this.get = function (key) {
        if (!key) {
          throw new TypeError(
            "Failed to execute 'getItem' on 'Storage': key required."
          );
        }

        if (typeof key !== "string") {
          return;
        }

        if (defS) {
          return window.sessionStorage.getItem(key);
        }

        return pairs[key] !== undefined ? pairs[key] : null;
      };

      this.set = function (key, value) {
        if (!key) {
          throw new TypeError(
            "Failed to execute 'setItem' on 'Storage': key required."
          );
        }
    
        if (typeof key !== "string") {
          return;
        }

        pairs[key] = value;

        if (defS) {
          return window.sessionStorage.setItem(key, value);
        }
      };

      this.remove = function (key) {
        if (!key) {
          throw new TypeError(
            "Failed to execute 'removeItem' on 'Storage': key required."
          );
        }

        if (typeof key !== "string") {
          return;
        }

        delete pairs[key];

        if (defS) {
          return window.sessionStorage.removeItem(key);
        }
      };

      this.clear = function () {
        pairs = {};

        if (defS) {
          return window.sessionStorage.clear();
        }
      };

      var sKeys = [];

      var addSessionKey = function (key) {
        if (sKeys.indexOf(key) === -1) {
          sKeys.push(key);
        }
      };

      this.setS = function (key, val) {
        let session = this.get("session");
        if (!session) {
          return;
        }

        addSessionKey(key);
        this.set(session + ":" + key, val);
      };

      this.getS = function (key) {
        let session = this.get("session");
        if (!session) {
          return null;
        }

        return this.get(session + ":" + key);
      };

      this.removeS = function (key) {
        let session = this.get("session");
        if (!session) {
          return;
        }

        let i = sKeys.indexOf(key);
        if (i !== -1) {
          sKey.splice(i, 1);
        }
        return this.remove(session + ":" + key);
      };

      this.clearS = function () {
        let session = this.get("session");
        if (!session) {
          return;
        }

        sKeys.forEach(function (key) {
          self.removeS(key);
        });  
      };
    }

		var lStore = new LocalStore();
		var sStore = new SessionStore();

		util.lStore = lStore;
		util.sStore = sStore;
	}());


  const TFA_REQUIRED = "TFARequired",
    TFA_SETUP_REQUIRED = "TFASetupRequired",
    TFA_EMAIL_EXPIRES = "TFAEmailExpires",
    CHANGE_PASSWORD_REQUIRED = "ChangePasswordRequired",
    REMEMBERED = "wc_remembered",
    SESSION = "session",
    SESSION_EXPIRED = "wc_session_expired",
    NEW_SESSION = "new_session",
    TFA_REMEMBERED = "wc_tfa_remembered",
    TOKEN = "token",
    TOKEN_2FA = "token_2fa",
    PARTIAL = "partial",
    CSRF = "wc_csrf_token",
    HAS_AUTHENTICATOR = "has_authenticator";

	(function () {
		var sStore = util.sStore;
		var lStore = util.lStore;

    function SessionManager() {
      var self = this;

			this.getSession = function () {
				return sStore.get(SESSION);
			};

			this.setSession = function (session) {
				sStore.set(SESSION, session);
			};

      this.setCSRFToken = function (csrf) {
        sStore.set(CSRF, csrf);
      };

      this.getCSRFToken = function () {
        return sStore.get(CSRF) || "";
      };

      this.getToken = function () {
        return sStore.get(TOKEN);
      };

      this.setToken = function (token) {
        sStore.set(TOKEN, token);
      };

      this.setTFAEmailExpires = function (nVal) {
        if (!!nVal) {
          sStore.set(TFA_EMAIL_EXPIRES, nVal);
        }
      };

      this.getTFAEmailExpires = function () {
        let nVal = sStore.get(TFA_EMAIL_EXPIRES);
        if (!!nVal) {
          return parseInt(nVal, 10);
        }

        return 0;
      };

			this.killSession = function () {
        sStore.clearS();
				sStore.remove(SESSION);
        sStore.remove(CSRF);
      };

      this.killToken = function () {
        sStore.remove(TOKEN);
        sStore.remove(TFA_REQUIRED);
        sStore.remove(TFA_SETUP_REQUIRED);
        sStore.remove(CHANGE_PASSWORD_REQUIRED);
      };

			this.getUser = function () {
				return punycode ? punycode.emailToText(sStore.get("user")) : sStore.get("user");
			};

			this.getWCUser = function () {
		    return punycode ? punycode.emailToText(lStore.get("wc_user")) : lStore.get("wc_user");
      };

      this.setUser = function (user) {
        sStore.set("user", punycode.emailToPuny(user));
      };

      this.setWCName = function (name) {
        lStore.set("wc_name", name);
      };

      this.setHasAuthenticator = function (bHasAuthenticator) {
        sStore.set(HAS_AUTHENTICATOR, bHasAuthenticator);
      };

      this.getHasAuthenticator = function () {
        let hasAuthenticator = sStore.get(HAS_AUTHENTICATOR);
        return hasAuthenticator === "true" || hasAuthenticator === "1" || hasAuthenticator === "yes";
      };

      this.setTFARequired = function (bSet) {
        if (!bSet) {
          sStore.remove(TFA_REQUIRED);
          return;
        }
        sStore.set(TFA_REQUIRED, !!bSet);
      };

      this.setTFASetupRequired = function (bSet) {
        if (!bSet) {
          sStore.remove(TFA_SETUP_REQUIRED);
          return;
        }
        sStore.set(TFA_SETUP_REQUIRED, !!bSet);
      };

      this.setChangePasswordRequired = function (bSet) {
        if (!bSet) {
          sStore.remove(CHANGE_PASSWORD_REQUIRED);
          return;
        }
        sStore.set(CHANGE_PASSWORD_REQUIRED, !!bSet);
      };

      this.remember = function (user) {
        lStore.set(REMEMBERED, user);
      };

      this.remembered = function (user) {
        let rUser = lStore.get(REMEMBERED);
        if (!is.string(rUser) || !is.string(user)) {
          return false;
        }

        return rUser.toLowerCase() === user.toLowerCase();
      };

      this.unremember = function () {
        if (lStore.get("Devel")) {
          console.trace("removed wc_remembered");
        }
        lStore.remove(REMEMBERED);
      };

      this.rememberTFA = function (user) {
        lStore.set(TFA_REMEMBERED, user);
      };

      this.rememberedTFA = function (user) {
        let rUser = lStore.get(TFA_REMEMBERED);
        if (!is.string(rUser) || !is.string(user)) {
          return false;
        }

        return rUser.toLowerCase() === user.toLowerCase();
      };

      this.unrememberTFA = function () {
        lStore.remove(TFA_REMEMBERED);
      };

      this.credentials = util.credentialsService;

      this.credentials.on("credentials-authentication-success", "session-manager", res => {
        if (res.name) {
          self.setWCName(res.name);
        }

        if (res.user) {
          self.setUser(res.user);
        }

        if (res.warning) {
          console.log(res.warning);
          if (res.new_session) {
            res.session = res.new_session;
          }
          self.setTFASetupRequired(false);
          self.setTFARequired(false);
          self.setChangePasswordRequired(false);
          switch (res.warning) {
            case "TwoFactorAuthRequired":
              if (res.token) {
                self.setToken(res.token);
                self.setUser(res.user);
                if (res.remembered) {
                  self.remember(self.getWCUser());
                }
                self.setTFARequired(true);
                if (res.partial) {
                  self.setPartialEmail(res.partial);
                }

                self.setHasAuthenticator(!!res.has_authenticator);
              }
              break;
            case "TwoFactorAuthSetupRequired":
              if (res.token && res.session) {
                self.setToken(res.token);
                self.setSession(res.session);
                self.setUser(res.user);
                if (res.remembered) {
                  self.remember(self.getWCUser());
                }
                self.setTFASetupRequired(true);
                if (!!res.two_factor_email_expires) {
                  self.setTFAEmailExpires(res.two_factor_email_expires);
                }
              }
              break;
            case "OldPassword":
              self.setToken(res.token);
              self.setUser(self.getWCUser());
              self.setChangePasswordRequired(true);
              if (res.error && res.error === "NoEditPassword") {
                res.error = "ChangePassword";
                self.setChangePasswordRequired(false);
              }
              break;
            default:
          }
          return;
        }

        if (res.useType === "login" && res.remembered) {
          self.remember(self.getWCUser());
        }

        if (res.new_session) {
          res.session = res.new_session;
        }

        if (res.session) {
          self.setSession(res.session);
        }

        if (res.useType === "2fa" && res.authed && res.session) {
          self.killToken();
          if (res.remembered) {
            self.rememberTFA(res.user);
          }
          else {
            self.unrememberTFA();
          }
        }
      });

      this.deviceRegistrationAlreadyOffered = function () {
        return self.credentials.deviceRegistrationAlreadyOffered();
      };

      this.offerDeviceRegistration = function () {
        self.credentials.offerDeviceRegistration();
      };
		}

		util.sessionManager = new SessionManager();
	
	}());

	function APIController () {
		var self = this;
		$.extend(this, new util.Emitter());
		var baseURL = "/WorldClientAPI/";

		var getOptions = function (type, url, json) {
			var options = { type: type, url: baseURL + url, dataType: "json" };
			if ((type === "get" || type === "delete" ) && json) {
        options.url += "?request=" + util.base64Encode(JSON.stringify(json));
			}
			else {
				options.data = JSON.stringify(json);
			}

			options.headers = {};
			if (type === "put" || type === "post") {
				options.headers["Content-Type"] = "application/json";
			}

			var session = util.sessionManager.getSession();
			if (session) {
				options.headers.Authorization = "Bearer " + session

        var csrfToken = util.sessionManager.getCSRFToken();
        if (csrfToken) {
            options.headers["X-CSRF-Token"] = csrfToken;
        }
			}


			return options;
		};

		this.get = function (url, json) {
			var request = $.ajax(getOptions("get", url, json));
			return request.fail(function (req, status, err) {
				self.emit("error", status + " | " + err);
			}).then(function (res) {
				if (!res) {
					self.emit("error", "The server did not respond.");
				}

				if (res && res.error) {
					self.emit("error", res.error);
        }

        if (res.csrf_token) {
          util.sessionManager.setCSRFToken(res.csrf_token);
          delete res.csrf_token;
        }

				return res;
			});
		};

		this.post = function (url, json) {
			var request = $.ajax(getOptions("post", url, json));
			return request.fail(function (req, status, err) {
				self.emit("error", status + " | " + err);
			}).then(function (res) {
				if (!res) {
					self.emit("error", "The server did not respond.");
				}

				if (res && res.error) {
					self.emit("error", res.error);
        }

        if (res.csrf_token) {
          util.sessionManager.setCSRFToken(res.csrf_token);
          delete res.csrf_token;
        }

				return res;
			});
		};

		this.put = function (url, json) {
			var request = $.ajax(getOptions("put", url, json));
			return request.fail(function (req, status, err) {
				self.emit("error", status + " | " + err);
			}).then(function (res) {
				if (!res) {
					self.emit("error", "The server did not respond.");
				}

				if (res && res.error) {
					self.emit("error", res.error);
        }

        if (res.csrf_token) {
          util.sessionManager.setCSRFToken(res.csrf_token);
          delete res.csrf_token;
        }

				return res;
			});
		};

		this.del = function (url, json) {
			var request = $.ajax(getOptions("delete", url, json));
			return request.fail(function (req, status, err) {
				self.emit("error", status + " | " + err);
			}).then(function (res) {
				if (!res) {
					self.emit("error", "The server did not respond.");
				}

				if (res && res.error) {
					self.emit("error", res.error);
				}

        if (res.csrf_token) {
          util.sessionManager.setCSRFToken(res.csrf_token);
          delete res.csrf_token;
        }

				return res;
			});
		};

		this.lStore = util.lStore;
		this.sStore = util.sStore;
		this.sessionManager = util.sessionManager;
	}

  if (!$WC.constructors) {
    $WC.constructors = {};
  }

  $WC.constructors.Emitter = util.Emitter;

	$WC.API = new APIController();
}());
(function ($WC){
     //Array.indexOf Polyfill
    if (!Array.prototype.indexOf) {
        Array.prototype.indexOf = function (searchElement, fromIndex) {
            var k; if (this === null) { throw new TypeError('"this" is null or not defined'); }
            var O = Object(this); var len = O.length >>> 0; if (len === 0) { return -1; }
            var n = +fromIndex || 0; if (Math.abs(n) === Infinity) { n = 0; }
            if (n >= len) { return -1; } k = Math.max(n >= 0 ? n : len - Math.abs(n), 0);
            while (k < len) { if (k in O && O[k] === searchElement) { return k; } k++; }
            return -1;
        };
    }

    // Should we redirect the user to the Pro theme?
    if (document.location.href.toLowerCase().indexOf("theme=") === -1) {
      var ua = navigator.userAgent.toLowerCase();
      if (ua.indexOf("iphone") !== -1 || ua.indexOf("android") !== -1 || ua.indexOf("windows ce") !== -1 || ua.indexOf("playstation portable") !== -1 || ua.indexOf("blackberry") !== -1 || ua.indexOf("ipad") !== -1 || ua.indexOf("iemobile") !== -1 || ua.indexOf("playbook") !== -1) {
        var d = document.documentElement.style;
        if ((('flexWrap' in d) || ('WebkitFlexWrap' in d) || ('msFlexWrap' in d)) && window.sessionStorage) {
          localStorage.setItem("theme", "Pro");
          document.location.href = "/webmail/index.html";
          return;
        }
        else {
          if (localStorage) {
            localStorage.setItem("theme", "Lite");
          }
          document.location.href = "/WorldClient.dll?View=Logon&Theme=Lite";
          return;
        }
      }
    }

    $WC.languages.pop();
    var langSwitch = { "en-US": "en", "en-GB": "uk", "en-AU": "uk",
        "en-NZ": "uk", "en-CA": "uk", "en-ZA": "uk", "fr-FR": "fr",
        "fr-CA": "fc", "fr-CH": "fr", "zh-CN": "zh", "zh-TW": "tw",
        "de-AT": "de", "de-DE": "de", "de-LI": "de", "de-CH": "de",
        "pt-BR": "pt", "pt-PT": "pt", "it-IT": "it", "it-CH": "it",
        "nb": "no", "es-419": "es", "sh": "sr"
    },

    language = localStorage.getItem("lang") || ($WC.useBrowserLang ? (navigator.userLanguage ? navigator.userLanguage : navigator.language) : $WC.lang);

    if (typeof language !== 'undefined') {
        language = langSwitch[language] || language;
        if ($WC.lang !== language && $WC.languages.indexOf(language) !== -1) {
            $WC.lang = language;
        }
    }

    var setSelectPlaceholderColor = function (el) {
        $(el).toggleClass('select-placeholder', !el.value);
        $(el).on("change", function () {
            $(this).toggleClass('select-placeholder', !this.value);
        });
    };

    var storeKeyPair = function (pair) {
      if (document.location.protocol !== "https:" || !window.WebCrypto || !WebCrypto.exportPublicKey) {
        return;
      }

      WebCrypto.exportPublicKey(pair.publicKey).then(function (exported) {
        localStorage.setItem("webmail_key_b", exported);
      });

      WebCrypto.exportPrivateKey(pair.privateKey).then(function (exported) {
        localStorage.setItem("webmail_key_a", exported);
      });
    };

    var updateTranslationStrings = function (strs) {
        if (strs.assistance) {
            $('#assistance').text(strs.assistance);
        }
        if (strs.emailAddress) {
            $('#User').attr('placeholder', strs.emailAddress);
        }
        if (strs.password) {
            $('#Password').attr('placeholder', strs.password);
        }
        if (strs.logon) {
            $('#Logon').text(strs.logon).append(' <i class="fa fa-arrow-right fa-lg"></i>');
            $('#SignInHeading').text(strs.logon);
        }
        if (strs.createAccount) {
            $('#createAccountTranslationString').text(strs.createAccount).append(' <i class="fa fa-arrow-right fa-lg"></i>');
        }
        if (strs.language) {
            $('#languageTranslationString').text(strs.language);
        }
        if (strs.theme) {
            $('#themeTranslationString').text(strs.theme);
        }
        if (strs.help) {
            $('#helpTranslation').text(strs.help);
        }
        if (strs.forgotPassword) {
            $("#passwordRecovery").text(strs.forgotPassword);
        }
        if (strs.whatsNew) {
            $("#whatsNewTranslation").text(strs.whatsNew);
        }
        if (strs.updateAvailable) {
            $("#updateAvailable").text(strs.updateAvailable);
        }
        if (strs.unregistered) {
            $("#unregistered").text(strs.unregistered);
        }
        if (strs.termsOfUseCheck) {
            $("#termsOfUseCheck").text(strs.termsOfUseCheck);
        }
        if (strs.termsOfUse) {
            $("#termsOfUse").text(strs.termsOfUse);
        }
        if (strs.rememberMeTitle) {
            $("#RememberMe").attr("title", strs.rememberMeTitle);
        }
        if (strs.rememberMeOption) {
            $("#rememberMeOption").text(strs.rememberMeOption);
        }
        if (strs.showPasswordOption) {
            $(".toggle-show-password.fa-eye").attr("title", strs.showPasswordOption);
        }
        if (strs.hidePasswordOption) {
            $(".toggle-show-password.fa-eye-slash").attr("title", strs.hidePasswordOption);
        }
    },

    init = function () {
        var form = document.forms[0];

        $("#Lang").on("change", function () {
            $.ajax({
                "url": $WC.link + "?&TRANSLATION=1&THEME=" + $WC.theme + "&RETURNJAVASCRIPT=1&Lang=" + ($("#Lang").val() || $WC.lang),
                "dataType": "json"
            }).done(function (strs) {
                updateTranslationStrings(strs);
            });
        });

        $("#passwordRecovery").on("click", function () {
            document.location.href = $WC.link + '?View=PasswordRecovery&Lang=' + ($("#Lang").val() || $WC.lang) + '&User=' + encodeURIComponent(punycode.encodeEmail($("#User").val()));
        });

        $(".toggle-show-password").on("click", function () {
            var $this = $(this);
            var show = $this.hasClass("fa-eye");
            
            $this.toggleClass("fa-eye", !show).toggleClass("fa-eye-slash", show);
            var input = $this.data("input");
            $("#" + input).attr("type", show ? "text" : "password").focus();
        });

        if (document.getElementById('Lang')) {
            setSelectPlaceholderColor(document.getElementById('Lang'));
        }

        if (document.getElementById('Theme')) {
            setSelectPlaceholderColor(document.getElementById('Theme'));
        }

        try{
            if (self.parent.frames.length !== 0 && !self.parent.frames.Cypress) {
                self.parent.location=document.location;
            }
            
            if ($WC.theme && $("#Theme").length > 0) {
                SetOption('Theme', $WC.theme);
                $("#Theme").change();
            }
            if ($WC.lang && $("#Lang").length > 0) {
                SetOption('Lang', $WC.lang);
                $("#Lang").change();
            }
            
            if (form.User.value.trim().length > 0) {
                form.User.value = punycode.decodeEmail(form.User.value);
                form.Password.focus();
            }
            else {
                form.User.focus();
            }
        }
        catch(exception){}

        if (localStorage) {
            var savedTheme = localStorage.getItem("theme") || GetCookie("Theme"), savedLang = localStorage.getItem("lang");
            if (savedTheme !== null && /^[A-Za-z0-9]+$/.test(savedTheme)) {
                $("#Theme").val(savedTheme).change();
            }
            else {
                localStorage.removeItem("theme");
            }

            if ($WC.https && !!window.WebCrypto && WebCrypto.genKeyPair) {
              var key = localStorage.getItem("webmail_key_b");
              if (!key) {
                WebCrypto.genKeyPair().then(function (keyPair) {
                  storeKeyPair(keyPair);
                });
              }
            }
        }

        document.body.addEventListener("keyup", function (e) {
          displayInputMessage($(".warning-text"), e.getModifierState("CapsLock"), $WC.capsLockIsOn);
        });

        function enableWebAuthnLogin() {
          $("#WebAuthnLogin").show();

          $WC.API.sessionManager.killSession();
          $("#DeviceLogin").on("click", function () {
            document.getElementById('Logon').disabled = true;
            $("#DeviceLogin").attr("disabled", true);

            var rememberMe = form.RememberMe && form.RememberMe.checked;
            if (rememberMe) {
                var key = lStore.get("webmail_key_b");
                if (key) {
                    SetCookie("WCKey", key, 30, true, true);
                }
            }

            $("#statusMessage").text($WC.attemptingDeviceAuth);
            $WC.API.sessionManager.credentials.on("credentials-authentication-success", "logon", function (res) {
              SetCookie("User", form.User.value.trim());
              if ($WC.https && rememberMe && !!window.WebCrypto) {
                var wcData = GetCookie("WCData");
                var privateKey = lStore.get("webmail_key_a");
                if (wcData & wcData.indexOf(":") === -1) {
                  window.WebCrypto.importPrivateKey(privateKey).then(function (key) {
                    window.WebCrypto.sign(key, wcData).then(function (signature) {
                      wcData = wcData + ":" + signature;
                      SetCookie("WCDataSigned", wcData, 30, true, true);
                    })
                  });
                }
              }

              if (res.warning) {
                var user = encodeURIComponent(form.User.value.trim());
                switch (res.warning) {
                  case "TwoFactorAuthRequired":
                    if (res.token) {
                        document.location.href = "/WorldClient.dll?View=TwoFactorAuth&User=" + user + "&Token=" + encodeURIComponent(res.token);
                    }
                    break;
                  case "TwoFactorAuthSetupRequired":
                    if (res.token) {
                        document.location.href = "/WorldClient.dll?Session=" + res.session + "&View=Logon&User=" + user + "&Token=" + encodeURIComponent(res.token);
                    }
                    break;
                  case "OldPassword":
                    if (res.token) {
                        document.location.href = "/WorldClient.dll?View=ChangePassword&User=" + user + "&Token=" + encodeURIComponent(res.token);
                    }
                    break;
                  default:
                }
              }
              else if (res.session) {
                  document.location.href = "/WorldClient.dll?Session=" + res.session + "&View=Main";
              }
            });

            var user = form.User.value.trim();
            if (!user) {
              document.getElementById('Logon').disabled = false;
              $("#DeviceLogin").attr("disabled", false);
              $("#statusMessage").text($WC.unableToAuthenticateDevice);
              return;
            }
            user = punycode.encodeEmail(user);

            if (user !== GetCookie("User")) {
              SetCookie("User", user);
            }
            $WC.API.sessionManager.credentials.authenticate(user, $("#Lang").val(), $("#Theme").val(), rememberMe, "login");
          });

          $("#DeviceLogin").attr("disabled", !form.User.value.length);

          $(form.User).on("paste keyup change blur", function () {
            $("#DeviceLogin").attr("disabled", !form.User.value.length);
          });
        }

        if ($WC.https && $WC.allowWebAuthnLogin && $WC.API) {
          if ($WC.API.sessionManager.credentials.isAvailable()) {
            enableWebAuthnLogin();
          }

          $WC.API.sessionManager.credentials.on("credentials-authentication-failure", "logon", function (errorObj) {
            if (errorObj && typeof errorObj === "object") {
              console.log(errorObj.error.error_message);
              console.log(errorObj.error.reason);
            }
            $WC.API.sessionManager.credentials.off("credentials-authentication-success");
            $("#statusMessage").text($WC.unableToAuthenticateDevice);
            document.getElementById('Logon').disabled = false;
            $("#DeviceLogin").attr("disabled", false);
          });
        }

        form.onsubmit = function () {
            document.getElementById('Logon').disabled = true;
            $("#DeviceLogin").attr("disabled", true);
            var user = form.User.value.trim();
            if ("punycode" in window) {
                form.User.value = punycode.encodeEmail(user);
            }

            if (user !== GetCookie("User")) {
                SetCookie("User", user);
            }

            if (localStorage) {
                if ($("#Theme").length > 0 && savedTheme !== $("#Theme").val()) {
                    localStorage.setItem("theme", $("#Theme").val());
                    SetCookie("Theme", $("#Theme").val());
                }
                if ($("#Lang").length > 0 && savedLang !== $("#Lang").val()) {
                    localStorage.setItem("lang", $("#Lang").val());
                    SetCookie("Lang", $("#Lang").val());

                }
                localStorage.setItem("wc_user", user);
                if (document.location.protocol === "https:" && form.RememberMe && form.RememberMe.checked) {
                    localStorage.setItem("wc_remembered", user);
                    var key = localStorage.getItem("webmail_key_b");
                    if (key) {
                      SetCookie("WCKey", key, 30, true, true);
                    }
                }
            }
        };

    };

    $(document).ready(function () {
        init();
    });
}($WC));
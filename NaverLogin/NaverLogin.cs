using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace NaverLogin
{
    public static class NaverLogin
    {
        private static string deviceMemory = "";
        private static string downLink = "";
        private static string dpr = "";
        private static string ect = "";
        private static string rtt = "";
        private static string sec_ch_ua = "";
        private static string sec_ch_ua_arch = "";
        private static string sec_ch_ua_full_version = "";
        private static string sec_ch_ua_mobile = "";
        private static string sec_ch_ua_model = "";
        private static string sec_ch_ua_platform = "";
        private static string sec_ch_ua_platform_version = "";
        private static string viewport_width = "";

        public enum LoginResult
        {
            LoginSuccess,
            PasswordWrong,
            BlockAccount,
            ProtectAccount,
            Captcha,
            UnknownError
        }

        /// <summary>
        /// Bvsd 전용 uuid
        /// </summary>
        /// <param name="seq">재시도 횟수</param>
        /// <returns></returns>
        private static string GenerateBvsdUUID(int seq = 0)
        {
            List<string> hex_table = new List<string>();
            List<uint> rnd_table = new List<uint>();

            for (int i = 0; i < 256; i++)
            {
                hex_table.Add(Convert.ToString((i + 256), 16).Substring(1));
            }

            uint e = 0;
            for (int i = 0; i < 16; i++)
            {
                if ((i & 3) != 0)
                    e = (uint)(4294967296 * new Random(Guid.NewGuid().GetHashCode()).NextDouble());
                rnd_table.Add(((uint)e >> ((i & 3) << 3) & 255));
            }
            rnd_table[6] = 15 & rnd_table[6] | 64;

            int t = 0;
            string ret = hex_table[Convert.ToInt32(rnd_table[t++])] + hex_table[Convert.ToInt32(rnd_table[t++])] + hex_table[Convert.ToInt32(rnd_table[t++])] + hex_table[Convert.ToInt32(rnd_table[t++])] + "-" +
                         hex_table[Convert.ToInt32(rnd_table[t++])] + hex_table[Convert.ToInt32(rnd_table[t++])] + "-" +
                         hex_table[Convert.ToInt32(rnd_table[t++])] + hex_table[Convert.ToInt32(rnd_table[t++])] + "-" +
                         hex_table[Convert.ToInt32(rnd_table[t++])] + hex_table[Convert.ToInt32(rnd_table[t++])] + "-" +
                         hex_table[Convert.ToInt32(rnd_table[t++])] + hex_table[Convert.ToInt32(rnd_table[t++])] + hex_table[Convert.ToInt32(rnd_table[t++])] + hex_table[Convert.ToInt32(rnd_table[t++])] + hex_table[Convert.ToInt32(rnd_table[t++])] + hex_table[Convert.ToInt32(rnd_table[t++])];

            ret = ret + '-' + seq.ToString();
            return ret;
        }

        public static LoginResult Login(string id, string pw, out CookieContainer resultcookie)
        {
            resultcookie = new CookieContainer();

            // 디바이스 정보 생성
            deviceMemory = (8 * new Random(Guid.NewGuid().GetHashCode()).Next(1, 4)).ToString();
            downLink = "10";
            dpr = "1.0";
            ect = "4g";
            rtt = "0";
            sec_ch_ua = "\"Chromium\";v=\"92\", \" Not A;Brand\";v=\"99\", \"Microsoft Edge\";v=\"92\"";
            sec_ch_ua_arch = "x86";
            sec_ch_ua_full_version = "\"92.0.902.84\"";
            sec_ch_ua_mobile = "?0";
            sec_ch_ua_model = "\"\"";
            sec_ch_ua_platform = "Windows";
            sec_ch_ua_platform_version = "10.0";
            viewport_width = "1003";

            //로그인 IP보안 OFF (아이피 변경, 새로운 환경에서도 쿠키 유지됨)
            Uri target = new Uri("https://nid.naver.com/");
            resultcookie.Add(new Cookie("nid_enctp", "1") { Domain = target.Host });
            resultcookie.Add(new Cookie("nid_slevel", "-1") { Domain = target.Host });

            // 다이나믹 키 받기
            string strLoginPage = GetNaverLoginPage();

            string dynamicKey = Regex.Match(strLoginPage, @"dynamicKey""\s?value=""(.*)""").Groups[1].Value;

            // 1. 세션정보 가져오기
            string strSessionInfo = GetNaverSessionInfo(dynamicKey, resultcookie);

            if (String.IsNullOrWhiteSpace(strSessionInfo))
                return LoginResult.UnknownError;

            //세션정보에는 암호화에 필요한 값들이 콤마(,)로 구분되어 있다.
            string[] arrSessionInfo = strSessionInfo.Split(',');

            string strSessionKey = arrSessionInfo[0];
            string strSessionName = arrSessionInfo[1];
            string strPublicModulusKey = arrSessionInfo[2];
            string strPublicExponentKey = arrSessionInfo[3];

            // 2. 암호화할 문자 생성하기
            string strParam = ConvertPassword(strSessionKey, id, pw);

            // 3. 문자 암호화
            string strEncParam = EncryptRSA(strPublicModulusKey, strPublicExponentKey, strParam);

            // UUID 생성
            string uuid = GenerateBvsdUUID();

            // BVSD 생성
            string encData = "{\"a\":\"" + uuid + "\",\"b\":\"1.3.4\",\"c\":true,\"d\":[{\"i\":\"id\",\"a\":[],\"b\":{\"a\":[\"0," + id + "\"],\"b\":0},\"c\":\"\",\"d\":\"" + id + "\",\"e\":false,\"f\":false},{\"i\":\"pw\",\"a\":[],\"b\":{\"a\":[\"0,\"],\"b\":0},\"c\":\"\",\"d\":\"\",\"e\":true,\"f\":false}],\"h\":\"1f\",\"i\":{\"a\":\"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Safari/537.36 Edg/92.0.902.84\"}}";
            string bvsd = "{\"uuid\":\"" + uuid + "\",\"encData\":\"" + LZString.compressToEncodedURIComponent(encData) + "\"}";

            byte[] data = Encoding.ASCII.GetBytes($"localechange=&dynamicKey={dynamicKey}&encpw={strEncParam}&enctp=1&svctype=1&smart_LEVEL=-1&bvsd={bvsd}&encnm={strSessionName}&locale=ko_KR&url=https%3A%2F%2Fwww.naver.com&id=&pw=");
            HttpWebRequest postreq = (HttpWebRequest)HttpWebRequest.Create("https://nid.naver.com/nidlogin.login");
            postreq.Method = "POST";
            postreq.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Safari/537.36 Edg/92.0.902.84";
            postreq.Accept = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9";
            postreq.Headers.Add(HttpRequestHeader.AcceptLanguage, "ko,en;q=0.9,en-US;q=0.8");
            postreq.ContentType = "application/x-www-form-urlencoded";
            postreq.Headers["device-memory"] = deviceMemory;
            postreq.Headers["downlink"] = downLink;
            postreq.Headers["dpr"] = dpr;
            postreq.Headers["ect"] = ect;
            postreq.Headers["rtt"] = rtt;
            postreq.Headers["sec-ch-ua"] = sec_ch_ua;
            postreq.Headers["sec-ch-ua-arch"] = sec_ch_ua_arch;
            postreq.Headers["sec-ch-ua-full-version"] = sec_ch_ua_full_version;
            postreq.Headers["sec-ch-ua-mobile"] = sec_ch_ua_mobile;
            postreq.Headers["sec-ch-ua-model"] = sec_ch_ua_model;
            postreq.Headers["sec-ch-ua-platform"] = sec_ch_ua_platform;
            postreq.Headers["sec-ch-ua-platform-version"] = sec_ch_ua_platform_version;
            postreq.Headers["ssc-fetch-dest"] = "document";
            postreq.Headers["sec-fetch-mode"] = "navigate";
            postreq.Headers["sec-fetch-site"] = "same-site";
            postreq.Headers["sec-fetch-user"] = "?1";
            postreq.Headers["viewport-width"] = viewport_width;
            postreq.CookieContainer = resultcookie;
            postreq.ContentLength = data.Length;

            Stream requestStream = postreq.GetRequestStream();
            requestStream.Write(data, 0, data.Length);
            requestStream.Close();

            HttpWebResponse webResponse = (HttpWebResponse)postreq.GetResponse();
            if (webResponse.StatusCode == HttpStatusCode.OK)
            {
                resultcookie.Add(webResponse.Cookies);

                Stream responseStream = webResponse.GetResponseStream();
                StreamReader streamReader = new StreamReader(responseStream, Encoding.UTF8);

                string strResult = streamReader.ReadToEnd();

                streamReader.Close();
                responseStream.Close();
                webResponse.Close();

                if (strResult.Contains("location.replace"))
                {
                    string finalURL = Regex.Match(strResult, @"replace\(""(.*)""\)", RegexOptions.IgnoreCase).Groups[1].Value;
                    strResult = Fianlize(finalURL, resultcookie);

                    // 핸드폰 등록
                    if (strResult.Contains("contactInfo"))
                    {
                        finalURL = Regex.Match(strResult, @"replace\(""(.*)""\)", RegexOptions.IgnoreCase).Groups[1].Value;
                        strResult = Fianlize(finalURL, resultcookie);
                        strResult = Fianlize("https://nid.naver.com/user2/help/contactInfo.nhn?m=viewPhoneInfo", resultcookie);

                        string token_help = Regex.Match(strResult, @"token_help"" value=""(.*)"">", RegexOptions.IgnoreCase).Groups[1].Value;
                        strResult = SetviewPhoneInfo(token_help, resultcookie);
                    }

                    return LoginResult.LoginSuccess;
                }
                else if (strResult.Contains("잘못 입력 되었습니다"))
                    return LoginResult.PasswordWrong;
                else if (strResult.Contains("로그인 제한") || strResult.Contains("이용이 제한"))
                    return LoginResult.BlockAccount;
                else if (strResult.Contains("자동입력 방지문자"))
                    return LoginResult.Captcha;
                else if (strResult.Contains("아이디를 보호"))
                    return LoginResult.ProtectAccount;
                else
                    return LoginResult.UnknownError;
            }
            else
                return LoginResult.UnknownError;
        }

        private static string GetNaverLoginPage()
        {
            string strSessionInfo = String.Empty;

            HttpWebRequest req = (HttpWebRequest)HttpWebRequest.Create("https://nid.naver.com/nidlogin.login?mode=form&url=https%3A%2F%2Fwww.naver.com");
            req.Method = WebRequestMethods.Http.Get;
            req.Host = "nid.naver.com";
            req.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Safari/537.36 Edg/92.0.902.84";
            req.Accept = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9";
            req.Headers.Add(HttpRequestHeader.AcceptLanguage, "ko,en;q=0.9,en-US;q=0.8");
            req.Referer = "https://www.naver.com/";
            req.Headers["device-memory"] = deviceMemory;
            req.Headers["downlink"] = downLink;
            req.Headers["dpr"] = dpr;
            req.Headers["ect"] = ect;
            req.Headers["rtt"] = rtt;
            req.Headers["sec-ch-ua"] = sec_ch_ua;
            req.Headers["sec-ch-ua-arch"] = sec_ch_ua_arch;
            req.Headers["sec-ch-ua-full-version"] = sec_ch_ua_full_version;
            req.Headers["sec-ch-ua-mobile"] = sec_ch_ua_mobile;
            req.Headers["sec-ch-ua-model"] = sec_ch_ua_model;
            req.Headers["sec-ch-ua-platform"] = sec_ch_ua_platform;
            req.Headers["sec-ch-ua-platform-version"] = sec_ch_ua_platform_version;
            req.Headers["ssc-fetch-dest"] = "document";
            req.Headers["sec-fetch-mode"] = "navigate";
            req.Headers["sec-fetch-site"] = "same-site";
            req.Headers["sec-fetch-user"] = "?1";
            req.Headers["viewport-width"] = viewport_width;

            using (HttpWebResponse res = (HttpWebResponse)req.GetResponse())
            {
                StreamReader sr = new StreamReader(res.GetResponseStream(), Encoding.UTF8);
                string strResult = sr.ReadToEnd();

                try
                {
                    strSessionInfo = strResult;
                }
                finally
                {
                    if (sr != null)
                        sr.Close();
                }
            }
            return strSessionInfo;
        }

        private static string Fianlize(string url, CookieContainer logincookie)
        {
            string strSessionInfo = String.Empty;

            HttpWebRequest req = (HttpWebRequest)HttpWebRequest.Create(url);
            req.Method = WebRequestMethods.Http.Get;
            req.Host = "nid.naver.com";
            req.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Safari/537.36 Edg/92.0.902.84";
            req.Accept = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9";
            req.Headers.Add(HttpRequestHeader.AcceptLanguage, "ko,en;q=0.9,en-US;q=0.8");
            req.Headers["device-memory"] = deviceMemory;
            req.Headers["downlink"] = downLink;
            req.Headers["dpr"] = dpr;
            req.Headers["ect"] = ect;
            req.Headers["rtt"] = rtt;
            req.Headers["sec-ch-ua"] = sec_ch_ua;
            req.Headers["sec-ch-ua-arch"] = sec_ch_ua_arch;
            req.Headers["sec-ch-ua-full-version"] = sec_ch_ua_full_version;
            req.Headers["sec-ch-ua-mobile"] = sec_ch_ua_mobile;
            req.Headers["sec-ch-ua-model"] = sec_ch_ua_model;
            req.Headers["sec-ch-ua-platform"] = sec_ch_ua_platform;
            req.Headers["sec-ch-ua-platform-version"] = sec_ch_ua_platform_version;
            req.Headers["ssc-fetch-dest"] = "document";
            req.Headers["sec-fetch-mode"] = "navigate";
            req.Headers["sec-fetch-site"] = "same-site";
            req.Headers["sec-fetch-user"] = "?1";
            req.Headers["viewport-width"] = viewport_width;
            req.CookieContainer = logincookie;

            using (HttpWebResponse res = (HttpWebResponse)req.GetResponse())
            {
                StreamReader sr = new StreamReader(res.GetResponseStream(), Encoding.UTF8);
                string strResult = sr.ReadToEnd();

                try
                {
                    strSessionInfo = strResult;
                }
                finally
                {
                    if (sr != null)
                        sr.Close();
                }
            }
            return strSessionInfo;
        }

        private static string SetviewPhoneInfo(string token_help, CookieContainer logincookie)
        {
            string strSessionInfo = String.Empty;

            byte[] data = Encoding.ASCII.GetBytes($"token_help={token_help}&tp=4&step=&register=on&internationalCode=82&phoneNo=");
            HttpWebRequest req = (HttpWebRequest)HttpWebRequest.Create("https://nid.naver.com/user2/help/contactInfo.nhn?m=setPhoneInfo");
            req.Method = WebRequestMethods.Http.Post;
            req.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Safari/537.36 Edg/92.0.902.84";
            req.ContentType = "application/x-www-form-urlencoded";
            req.CookieContainer = logincookie;
            req.ContentLength = data.Length;

            Stream requestStream = req.GetRequestStream();
            requestStream.Write(data, 0, data.Length);
            requestStream.Close();

            using (HttpWebResponse res = (HttpWebResponse)req.GetResponse())
            {
                logincookie.Add(res.Cookies);

                StreamReader sr = new StreamReader(res.GetResponseStream(), Encoding.UTF8);
                string strResult = sr.ReadToEnd();

                try
                {
                    strSessionInfo = strResult;
                }
                finally
                {
                    if (sr != null)
                        sr.Close();
                }
            }
            return strSessionInfo;
        }

        private static string GetNaverSessionInfo(string dynamicKey, CookieContainer tempcookie)
        {
            string strSessionInfo = String.Empty;

            HttpWebRequest req = (HttpWebRequest)HttpWebRequest.Create($"https://nid.naver.com/dynamicKey/{dynamicKey}");
            req.Method = WebRequestMethods.Http.Get;
            req.Accept = "*/*";
            req.Host = "nid.naver.com";
            req.UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.159 Safari/537.36 Edg/92.0.902.84";
            req.Headers.Add(HttpRequestHeader.AcceptLanguage, "ko,en;q=0.9,en-US;q=0.8");
            req.Referer = "https://nid.naver.com/nidlogin.login?mode=form&url=https%3A%2F%2Fwww.naver.com";
            req.Headers["device-memory"] = deviceMemory;
            req.Headers["downlink"] = downLink;
            req.Headers["dpr"] = dpr;
            req.Headers["ect"] = ect;
            req.Headers["rtt"] = rtt;
            req.Headers["sec-ch-ua"] = sec_ch_ua;
            req.Headers["sec-ch-ua-arch"] = sec_ch_ua_arch;
            req.Headers["sec-ch-ua-full-version"] = sec_ch_ua_full_version;
            req.Headers["sec-ch-ua-mobile"] = sec_ch_ua_mobile;
            req.Headers["sec-ch-ua-model"] = sec_ch_ua_model;
            req.Headers["sec-ch-ua-platform"] = sec_ch_ua_platform;
            req.Headers["sec-ch-ua-platform-version"] = sec_ch_ua_platform_version;
            req.Headers["sec-fetch-dest"] = "empty";
            req.Headers["sec-fetch-mode"] = "cors";
            req.Headers["sec-fetch-site"] = "same-origin";
            req.Headers["viewport-width"] = viewport_width;
            req.CookieContainer = tempcookie;

            using (HttpWebResponse res = (HttpWebResponse)req.GetResponse())
            {
                StreamReader sr = new StreamReader(res.GetResponseStream(), Encoding.UTF8);
                string strResult = sr.ReadToEnd();

                try
                {
                    strSessionInfo = strResult;
                }
                finally
                {
                    if (sr != null)
                        sr.Close();
                }
            }
            return strSessionInfo;
        }

        private static string ConvertPassword(string strSessionKey, string strId, string strPassword)
        {
            string strResult = String.Empty;
            strResult += Convert.ToChar(strSessionKey.Length).ToString();
            strResult += strSessionKey;
            strResult += Convert.ToChar(strId.Length).ToString();
            strResult += strId;
            strResult += Convert.ToChar(strPassword.Length).ToString();
            strResult += strPassword;
            return strResult;
        }

        private static string EncryptRSA(string strPublicModulusKey, string strPublicExponentKey, string strTarget)
        {
            string strResult = String.Empty;

            // 공개키 생성
            RSAParameters publicKey = new RSAParameters()
            {
                Modulus = Enumerable.Range(0, strPublicModulusKey.Length)
                .Where(x => x % 2 == 0)
                .Select(x => Convert.ToByte(strPublicModulusKey.Substring(x, 2), 16))
                .ToArray()
                ,
                Exponent = Enumerable.Range(0, strPublicExponentKey.Length)
                .Where(x => x % 2 == 0)
                .Select(x => Convert.ToByte(strPublicExponentKey.Substring(x, 2), 16))
                .ToArray()
            };

            try
            {
                RSACryptoServiceProvider rsa = new RSACryptoServiceProvider();
                rsa.ImportParameters(publicKey);
                // 암호화 및 Byte => String 변환
                byte[] enc = rsa.Encrypt(Encoding.UTF8.GetBytes(strTarget), false);
                strResult = BitConverter.ToString(enc).Replace("-", "").ToLower();
            }
            catch (CryptographicException ex)
            {
                strResult = String.Empty;
            }

            return strResult;
        }
    }

    /// <summary>
    /// LZString.cs  / https://github.com/kreudom/lz-string-csharp/blob/master/LZString.cs
    /// </summary>
    public class LZString
    {
        static string keyStrBase64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
        static string keyStrUriSafe = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+-$";
        static Dictionary<string, Dictionary<char, int>> baseReverseDic = new Dictionary<string, Dictionary<char, int>>();
        private delegate char GetCharFromInt(int a);
        private static GetCharFromInt f = (a) => Convert.ToChar(a);
        private delegate int GetNextValue(int index);

        private static int getBaseValue(string alphabet, char character)
        {
            if (!baseReverseDic.ContainsKey(alphabet))
            {
                baseReverseDic[alphabet] = new Dictionary<char, int>();
                for (int i = 0; i < alphabet.Length; i++)
                {
                    baseReverseDic[alphabet][alphabet[i]] = i;
                }
            }
            return baseReverseDic[alphabet][character];
        }

        public static string compressToBase64(string input)
        {
            if (input == null) return "";
            string res = _compress(input, 6, (a) => keyStrBase64[a]);
            switch (res.Length % 4)
            {
                case 0: return res;
                case 1: return res + "===";
                case 2: return res + "==";
                case 3: return res + "=";
            }
            return null;
        }

        public static string decompressFromBase64(string input)
        {
            if (input == null) return "";
            if (input == "") return null;
            return _decompress(input.Length, 32, (index) => getBaseValue(keyStrBase64, input[index]));
        }

        public static string compressToUTF16(string input)
        {
            if (input == null) return "";
            return _compress(input, 15, (a) => f(a + 32)) + " ";
        }

        public static string decompressFromUTF16(string compressed)
        {
            if (compressed == null) return "";
            if (compressed == "") return null;
            return _decompress(compressed.Length, 16384, index => Convert.ToInt32(compressed[index]) - 32);
        }

        public static byte[] compressToUint8Array(string uncompressed)
        {
            string compressed = compress(uncompressed);
            byte[] buf = new byte[compressed.Length * 2];

            for (int i = 0, TotalLen = compressed.Length; i < TotalLen; i++)
            {
                int current_value = Convert.ToInt32(compressed[i]);
                buf[i * 2] = (byte)(((uint)current_value) >> 8);
                buf[i * 2 + 1] = (byte)(current_value % 256);
            }
            return buf;
        }

        public static string decompressFromUint8Array(byte[] compressed)
        {
            if (compressed == null) return "";
            else
            {
                int[] buf = new int[compressed.Length / 2];
                for (int i = 0, TotalLen = buf.Length; i < TotalLen; i++)
                {
                    buf[i] = ((int)compressed[i * 2]) * 256 + ((int)compressed[i * 2 + 1]);
                }
                char[] result = new char[buf.Length];
                for (int i = 0; i < buf.Length; i++)
                {
                    result[i] = f(buf[i]);
                }
                return decompress(new string(result));
            }
        }

        public static string compressToEncodedURIComponent(string input)
        {
            if (input == null) return "";
            return _compress(input, 6, (a) => keyStrUriSafe[a]);
        }

        public static string decompressFromEncodedURIComponent(string input)
        {
            if (input == null) return "";
            if (input == "") return null;
            input = input.Replace(' ', '+');
            return _decompress(input.Length, 32, (index) => getBaseValue(keyStrUriSafe, input[index]));
        }

        public static string compress(string uncompressed)
        {
            return _compress(uncompressed, 16, f);
        }

        private static string _compress(string uncompressed, int bitsPerChar, GetCharFromInt getCharFromInt)
        {
            if (uncompressed == null) return "";
            int i, value, ii, context_enlargeIn = 2, context_dictSize = 3, context_numBits = 2, context_data_val = 0, context_data_position = 0;
            Dictionary<string, bool> context_dictionaryToCreate = new Dictionary<string, bool>();
            Dictionary<string, int> context_dictionary = new Dictionary<string, int>();
            StringBuilder context_data = new StringBuilder();
            string context_c = "";
            string context_wc = "", context_w = "";

            for (ii = 0; ii < uncompressed.Length; ii++)
            {
                context_c = uncompressed[ii].ToString();
                if (!context_dictionary.ContainsKey(context_c))
                {
                    context_dictionary[context_c] = context_dictSize++;
                    context_dictionaryToCreate[context_c] = true;
                }
                context_wc = context_w + context_c;
                if (context_dictionary.ContainsKey(context_wc))
                {
                    context_w = context_wc;
                }
                else
                {
                    if (context_dictionaryToCreate.ContainsKey(context_w))
                    {
                        if (Convert.ToInt32(context_w[0]) < 256)
                        {
                            for (i = 0; i < context_numBits; i++)
                            {
                                context_data_val = (context_data_val << 1);
                                if (context_data_position == bitsPerChar - 1)
                                {
                                    context_data_position = 0;
                                    context_data.Append(getCharFromInt(context_data_val));
                                    context_data_val = 0;
                                }
                                else
                                {
                                    context_data_position++;
                                }
                            }
                            value = Convert.ToInt32(context_w[0]);
                            for (i = 0; i < 8; i++)
                            {
                                context_data_val = (context_data_val << 1) | (value & 1);
                                if (context_data_position == bitsPerChar - 1)
                                {
                                    context_data_position = 0;
                                    context_data.Append(getCharFromInt(context_data_val));
                                    context_data_val = 0;
                                }
                                else
                                {
                                    context_data_position++;
                                }
                                value = value >> 1;
                            }
                        }
                        else
                        {
                            value = 1;
                            for (i = 0; i < context_numBits; i++)
                            {
                                context_data_val = (context_data_val << 1) | value;
                                if (context_data_position == bitsPerChar - 1)
                                {
                                    context_data_position = 0;
                                    context_data.Append(getCharFromInt(context_data_val));
                                    context_data_val = 0;
                                }
                                else
                                {
                                    context_data_position++;
                                }
                                value = 0;
                            }
                            value = Convert.ToInt32(context_w[0]);
                            for (i = 0; i < 16; i++)
                            {
                                context_data_val = (context_data_val << 1) | (value & 1);
                                if (context_data_position == bitsPerChar - 1)
                                {
                                    context_data_position = 0;
                                    context_data.Append(getCharFromInt(context_data_val));
                                    context_data_val = 0;
                                }
                                else
                                {
                                    context_data_position++;
                                }
                                value = value >> 1;
                            }
                        }
                        context_enlargeIn--;
                        if (context_enlargeIn == 0)
                        {
                            context_enlargeIn = (int)Math.Pow(2, context_numBits);
                            context_numBits++;
                        }
                        context_dictionaryToCreate.Remove(context_w);
                    }
                    else
                    {
                        value = context_dictionary[context_w];
                        for (i = 0; i < context_numBits; i++)
                        {
                            context_data_val = (context_data_val << 1) | (value & 1);
                            if (context_data_position == bitsPerChar - 1)
                            {
                                context_data_position = 0;
                                context_data.Append(getCharFromInt(context_data_val));
                                context_data_val = 0;
                            }
                            else
                            {
                                context_data_position++;
                            }
                            value = value >> 1;
                        }
                    }
                    context_enlargeIn--;
                    if (context_enlargeIn == 0)
                    {
                        context_enlargeIn = (int)Math.Pow(2, context_numBits);
                        context_numBits++;
                    }
                    //Add wc to the dictionary
                    context_dictionary[context_wc] = context_dictSize++;
                    context_w = context_c;
                }
            }
            //Output the code for w
            if (context_w != "")
            {
                if (context_dictionaryToCreate.ContainsKey(context_w))
                {
                    if (Convert.ToInt32(context_w[0]) < 256)
                    {
                        for (i = 0; i < context_numBits; i++)
                        {
                            context_data_val = (context_data_val << 1);
                            if (context_data_position == bitsPerChar - 1)
                            {
                                context_data_position = 0;
                                context_data.Append(getCharFromInt(context_data_val));
                                context_data_val = 0;
                            }
                            else
                            {
                                context_data_position++;
                            }
                        }
                        value = Convert.ToInt32(context_w[0]);
                        for (i = 0; i < 8; i++)
                        {
                            context_data_val = (context_data_val << 1) | (value & 1);
                            if (context_data_position == bitsPerChar - 1)
                            {
                                context_data_position = 0;
                                context_data.Append(getCharFromInt(context_data_val));
                                context_data_val = 0;
                            }
                            else
                            {
                                context_data_position++;
                            }
                            value = value >> 1;
                        }
                    }
                    else
                    {
                        value = 1;
                        for (i = 0; i < context_numBits; i++)
                        {
                            context_data_val = (context_data_val << 1) | value;
                            if (context_data_position == bitsPerChar - 1)
                            {
                                context_data_position = 0;
                                context_data.Append(getCharFromInt(context_data_val));
                                context_data_val = 0;
                            }
                            else
                            {
                                context_data_position++;
                            }
                            value = 0;
                        }
                        value = Convert.ToInt32(context_w[0]);
                        for (i = 0; i < 16; i++)
                        {
                            context_data_val = (context_data_val << 1) | (value & 1);
                            if (context_data_position == bitsPerChar - 1)
                            {
                                context_data_position = 0;
                                context_data.Append(getCharFromInt(context_data_val));
                                context_data_val = 0;
                            }
                            else
                            {
                                context_data_position++;
                            }
                            value = value >> 1;
                        }
                    }
                    context_enlargeIn--;
                    if (context_enlargeIn == 0)
                    {
                        context_enlargeIn = (int)Math.Pow(2, context_numBits);
                        context_numBits++;
                    }
                    context_dictionaryToCreate.Remove(context_w);
                }
                else
                {
                    value = context_dictionary[context_w];
                    for (i = 0; i < context_numBits; i++)
                    {
                        context_data_val = (context_data_val << 1) | (value & 1);
                        if (context_data_position == bitsPerChar - 1)
                        {
                            context_data_position = 0;
                            context_data.Append(getCharFromInt(context_data_val));
                            context_data_val = 0;
                        }
                        else
                        {
                            context_data_position++;
                        }
                        value = value >> 1;
                    }
                }
                context_enlargeIn--;
                if (context_enlargeIn == 0)
                {
                    context_enlargeIn = (int)Math.Pow(2, context_numBits);
                    context_numBits++;
                }
            }
            //Mark the end of the stream
            value = 2;
            for (i = 0; i < context_numBits; i++)
            {
                context_data_val = (context_data_val << 1) | (value & 1);
                if (context_data_position == bitsPerChar - 1)
                {
                    context_data_position = 0;
                    context_data.Append(getCharFromInt(context_data_val));
                    context_data_val = 0;
                }
                else
                {
                    context_data_position++;
                }
                value = value >> 1;
            }

            //Flush the last char
            while (true)
            {
                context_data_val = (context_data_val << 1);
                if (context_data_position == bitsPerChar - 1)
                {
                    context_data.Append(getCharFromInt(context_data_val));
                    break;
                }
                else context_data_position++;
            }
            return context_data.ToString();
        }

        public static string decompress(string compressed)
        {
            if (compressed == null) return "";
            if (compressed == "") return null;
            return _decompress(compressed.Length, 32768, (index) => Convert.ToInt32(compressed[index]));
        }


        private struct dataStruct
        {
            public int val, position, index;
        }
        private static string _decompress(int length, int resetValue, GetNextValue getNextValue)
        {
            Dictionary<int, string> dictionary = new Dictionary<int, string>();
            int next, enlargeIn = 4, dictSize = 4, numBits = 3, i, bits, resb, maxpower, power;
            int c = 0;
            string entry = "", w;
            StringBuilder result = new StringBuilder();
            var data = new dataStruct() { val = getNextValue(0), position = resetValue, index = 1 };

            for (i = 0; i < 3; i++)
            {
                dictionary[i] = Convert.ToChar(i).ToString();
            }

            bits = 0;
            maxpower = (int)Math.Pow(2, 2);
            power = 1;
            while (power != maxpower)
            {
                resb = data.val & data.position;
                data.position >>= 1;
                if (data.position == 0)
                {
                    data.position = resetValue;
                    data.val = getNextValue(data.index++);
                }
                bits |= (resb > 0 ? 1 : 0) * power;
                power <<= 1;
            }

            switch (next = bits)
            {
                case 0:
                    bits = 0;
                    maxpower = (int)Math.Pow(2, 8);
                    power = 1;
                    while (power != maxpower)
                    {
                        resb = data.val & data.position;
                        data.position >>= 1;
                        if (data.position == 0)
                        {
                            data.position = resetValue;
                            data.val = getNextValue(data.index++);
                        }
                        bits |= (resb > 0 ? 1 : 0) * power;
                        power <<= 1;
                    }
                    c = Convert.ToInt32(f(bits));
                    break;
                case 1:
                    bits = 0;
                    maxpower = (int)Math.Pow(2, 16);
                    power = 1;
                    while (power != maxpower)
                    {
                        resb = data.val & data.position;
                        data.position >>= 1;
                        if (data.position == 0)
                        {
                            data.position = resetValue;
                            data.val = getNextValue(data.index++);
                        }
                        bits |= (resb > 0 ? 1 : 0) * power;
                        power <<= 1;
                    }
                    c = Convert.ToInt32(f(bits));
                    break;
                case 2:
                    return "";
            }
            dictionary[3] = Convert.ToChar(c).ToString();
            w = Convert.ToChar(c).ToString();
            result.Append(Convert.ToChar(c));
            while (true)
            {
                if (data.index > length)
                {
                    return "";
                }

                bits = 0;
                maxpower = (int)Math.Pow(2, numBits);
                power = 1;
                while (power != maxpower)
                {
                    resb = data.val & data.position;
                    data.position >>= 1;
                    if (data.position == 0)
                    {
                        data.position = resetValue;
                        data.val = getNextValue(data.index++);
                    }
                    bits |= (resb > 0 ? 1 : 0) * power;
                    power <<= 1;
                }

                switch (c = bits)
                {
                    case 0:
                        bits = 0;
                        maxpower = (int)Math.Pow(2, 8);
                        power = 1;
                        while (power != maxpower)
                        {
                            resb = data.val & data.position;
                            data.position >>= 1;
                            if (data.position == 0)
                            {
                                data.position = resetValue;
                                data.val = getNextValue(data.index++);
                            }
                            bits |= (resb > 0 ? 1 : 0) * power;
                            power <<= 1;
                        }

                        dictionary[dictSize++] = f(bits).ToString();
                        c = dictSize - 1;
                        enlargeIn--;
                        break;
                    case 1:
                        bits = 0;
                        maxpower = (int)Math.Pow(2, 16);
                        power = 1;
                        while (power != maxpower)
                        {
                            resb = data.val & data.position;
                            data.position >>= 1;
                            if (data.position == 0)
                            {
                                data.position = resetValue;
                                data.val = getNextValue(data.index++);
                            }
                            bits |= (resb > 0 ? 1 : 0) * power;
                            power <<= 1;
                        }
                        dictionary[dictSize++] = f(bits).ToString();
                        c = dictSize - 1;
                        enlargeIn--;
                        break;
                    case 2:
                        return result.ToString();
                }

                if (enlargeIn == 0)
                {
                    enlargeIn = (int)Math.Pow(2, numBits);
                    numBits++;
                }

                if (dictionary.ContainsKey(c))
                {
                    entry = dictionary[c];
                }
                else
                {
                    if (c == dictSize)
                    {
                        entry = w + w[0].ToString();
                    }
                    else
                    {
                        return null;
                    }
                }
                result.Append(entry);

                //Add w+entry[0] to the dictionary.
                dictionary[dictSize++] = w + entry[0].ToString();
                enlargeIn--;
                w = entry;
                if (enlargeIn == 0)
                {
                    enlargeIn = (int)Math.Pow(2, numBits);
                    numBits++;
                }
            }
        }
    }
}

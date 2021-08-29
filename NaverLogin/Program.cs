using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text;
using System.Threading.Tasks;
using static NaverLogin.NaverLogin;

namespace NaverLogin
{
    class Program
    {
        static void Main(string[] args)
        {
            string naverid = "네이버 아이디";
            string naverpw = "네이버 비밀번호";

            CookieContainer logincookie = new CookieContainer();
            var loginResult = NaverLogin.Login(naverid, naverpw, out logincookie);

            if (loginResult == LoginResult.LoginSuccess)
                Console.WriteLine("로그인이 완료되었습니다.");
            else if (loginResult == LoginResult.PasswordWrong)
                Console.WriteLine("아이디 또는 비밀번호가 올바르지 않습니다.");
            else if (loginResult == LoginResult.BlockAccount)
                Console.WriteLine("이용이 정지된 계정입니다.");
            else if (loginResult == LoginResult.ProtectAccount)
                Console.WriteLine("보호조치 아이디입니다.");
            else if (loginResult == LoginResult.Captcha)
                Console.WriteLine("보안문자가 표시된 아이디입니다.");
            else if (loginResult == LoginResult.UnknownError)
                Console.WriteLine("알 수 없는 오류로 로그인에 실패했습니다.");

            Console.ReadLine();
        }
    }
}

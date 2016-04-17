#!/usr/bin/env python3

import time
import uuid
import random
import string
import threading
import requests as r

from ws4py.exc import WebSocketException
from ws4py.client.threadedclient import WebSocketClient
from httpchecker import *

GET = 'GET'
POST = 'POST'
PORT = 8888
WSPORT = 9999

OPEN = threading.Event()
DONE = threading.Event()

class DummyClient(WebSocketClient):
	def setargs(self, login, text):
		self.login = login
		self.text = text

	def debug(self, msg):
		sys.stderr.write('%s\n' % msg)

	#def handshake_ok(self):
		#self.debug('WebSocket handshake ok')
		#OPEN.set()

	def opened(self):
		self.debug('WebSocket opened')

	def closed(self, code, reason=None):
		self.debug('WebSocket closed, code: "{}", reason: "{}"'.format(code, reason))

	def received_message(self, msg):
		if not msg or not msg.is_text:
			return
		data = str(msg)
		self.debug('WS msg: ' + data)
		try:
			if data == 'hello':
				self.debug('WebSocket hello received')
				OPEN.set()
				return
			if (not self.login or data.find(self.login) >= 0) and (not self.text or data.find(self.text) >= 0):
			#result = json.loads(data)
			#if result.get('login') != self.login:
				#return
			#self.debug('WebSocket self posted message: ' + data)
			#if data.find(self.text) >= 0:
				DONE.set()
		except ValueError:
			self.debug(traceback.format_exc())
			self.debug('WebSocket parse message failed: ' + data)

class Checker(HttpCheckerBase):
	def session(self, addr):
		s = r.Session()
		s.headers['User-Agent'] = self.randua()
		return s

	def url(self, addr, suffix):
		return 'http://{}:{}{}'.format(addr, PORT, suffix)

	def parseresponse(self, response, path):
		try:
			if response.status_code != 200:
				raise HttpWebException(response.status_code, path)
			try:
				result = response.json()
				#self.debug(result)
				return result
			except ValueError:
				self.debug(traceback.format_exc())
				raise r.exceptions.HTTPError('failed to parse response')
		finally:
			response.close()

	def parsestringresponse(self, response, path):
		try:
			if response.status_code != 200:
				raise HttpWebException(response.status_code, path)
			result = response.text
			return result
		finally:
			response.close()

	def jpost(self, s, addr, suffix, data = None):
		response = s.post(self.url(addr, suffix), data, timeout=5)
		return self.parseresponse(response, suffix)

	def spost(self, s, addr, suffix, data = None):
		response = s.post(self.url(addr, suffix), data, timeout=5)
		return self.parsestringresponse(response, suffix)

	def jget(self, s, addr, suffix):
		response = s.get(self.url(addr, suffix), timeout=5)
		return self.parseresponse(response, suffix)

	def sget(self, s, addr, suffix):
		response = s.get(self.url(addr, suffix), timeout=5)
		return self.parsestringresponse(response, suffix)

	def randword(self):
		word = ''
		rnd = random.randrange(2,10)
		for i in range(rnd):
			word += random.choice(string.ascii_lowercase)
		return word

	def randphrase(self):
		phrase = ''
		rnd = random.randrange(1,5)
		for i in range(rnd):
			phrase += ' ' + self.randword();
		return phrase.lstrip()

	def randua(self):
		return random.choice([
			'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_10_1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/37.0.2062.124 Safari/537.36',
			'Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/39.0.2171.71 Safari/537.36',
			'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/41.0.2227.0 Safari/537.36',
			'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/46.0.2490.80 Safari/537.36',
			'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/49.0.2623.110 Safari/537.36',

			'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.125 YaBrowser/14.8.1985.11875 Safari/537.36',
			'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_9_5) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.125 YaBrowser/14.8.1985.12017 Safari/537.36',
			'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.125 YaBrowser/14.8.1985.12018 Safari/537.36',
			'Mozilla/5.0 (Windows NT 6.1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.125 YaBrowser/14.8.1985.12084 Safari/537.36',
			'Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/36.0.1985.125 YaBrowser/14.8.1985.12084 Safari/537.36',

			'Mozilla/5.0 (X11; Linux i686) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/33.0.1750.152 Chrome/33.0.1750.152 Safari/537.36',
			'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/34.0.1847.116 Chrome/34.0.1847.116 Safari/537.36',
			'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/36.0.1985.125 Chrome/36.0.1985.125 Safari/537.36',
			'Mozilla/5.0 (X11; Linux i686) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/38.0.2125.111 Chrome/38.0.2125.111 Safari/537.36',
			'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Ubuntu Chromium/38.0.2125.111 Chrome/38.0.2125.111 Safari/537.36',

			'Mozilla/5.0 (X11; Linux i586; rv:31.0) Gecko/20100101 Firefox/31.0',
			'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:31.0) Gecko/20130401 Firefox/31.0',
			'Mozilla/5.0 (X11; OpenBSD amd64; rv:28.0) Gecko/20100101 Firefox/28.0',
			'Mozilla/5.0 (Windows NT 6.3; rv:36.0) Gecko/20100101 Firefox/36.0',
			'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:36.0) Gecko/20100101 Firefox/36.0',
			'Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:41.0) Gecko/20100101 Firefox/41.0',

			'Mozilla/5.0 (compatible; MSIE 9.0; Windows NT 6.1; Trident/5.0)',
			'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; Trident/6.0)',
			'Mozilla/5.0 (compatible; MSIE 10.0; Windows NT 6.1; WOW64; Trident/6.0)',
			'Mozilla/5.0 (compatible, MSIE 11, Windows NT 6.1; Trident/7.0; rv:11.0) like Gecko',
			'Mozilla/5.0 (compatible, MSIE 11, Windows NT 6.3; Trident/7.0; rv:11.0) like Gecko',

			'Opera/9.80 (Windows NT 6.1; U; es-ES) Presto/2.9.181 Version/12.00',
			'Opera/9.80 (Windows NT 6.0) Presto/2.12.388 Version/12.14',
			'Opera/9.80 (X11; Linux i686; Ubuntu/14.10) Presto/2.12.388 Version/12.16',
			'Opera/9.80 (Windows NT 6.1) Presto/2.12.388 Version/12.16',
			'Opera/9.80 (Windows NT 6.1; Win64; x64) Presto/2.12.388 Version/12.17'
		])

	def randfreqengword(self):
		return random.choice([
			'the','of','and','to','a','in','is','you','are','for','that','or','it','as','be','on','your','with','can',
			'have','this','an','by','not','but','at','from','I','they','more','will','if','some','there','what','about',
			'which','when','one','their','all','also','how','many','do','has','most','people','other','time','so','was',
			'we','these','may','like','use','into','than','up','out','who','them','make','because','such','through','get',
			'work','even','different','its','no','our','new','film','just','only','see','used','good','water','been','need',
			'should','very','any','history','often','way','well','art','know','were','then','my','first','would','money',
			'each','over','world','information','map','find','where','much','take','two','want','important','family',
			'those','example','while','he','look','government','before','help','between','go','own','however','business',
			'us','great','his','being','another','health','same','study','why','few','game','might','think','free','too',
			'had','hi','right','still','system','after','computer','best','must','her','life','since','could','does','now',
			'during','learn','around','usually'
		])

	def randengword(self):
		return random.choice([
			'form','meat','air','day','place','become','number','public','read','keep','part','start','year',
			'every','field','large','once','available','down','give','fish','human','both','local','sure','something','without',
			'come','me','back','better','general','process','she','heat','thanks','specific','enough','long','lot','hand',
			'popular','small','though','experience','include','job','music','person','really','although','thank','book','early',
			'reading','end','method','never','less','play','able','data','feel','high','off','point','type','whether','food',
			'understanding','here','home','certain','economy','little','theory','tonight','law','put','under','value','always',
			'body','common','market','set','bird','guide','provide','change','interest','literature','sometimes','problem','say',
			'next','create','simple','software','state','together','control','knowledge','power','radio','ability','basic','course',
			'economics','hard','add','company','known','love','past','price','size','away','big','internet','possible','television',
			'three','understand','various','yourself','card','difficult','including','list','mind','particular','real','science',
			'trade','consider','either','library','likely','nature','fact','line','product','care','group','idea','risk','several',
			'someone','temperature','united','word','fat','force','key','light','simply','today','training','until','major','name',
			'personal','school','top','current','generally','historical','investment','left','national','amount','level','order',
			'practice','research','sense','service','area','cut','hot','instead','least','natural','physical','piece','show',
			'society','try','check','choose','develop','second','useful','web','activity','boss','short','story','call','industry',
			'last','media','mental','move','pay','sport','thing','actually','against','far','fun','house','let','page','remember',
			'term','test','within','along','answer','increase','oven','quite','scared','single','sound','again','community',
			'definition','focus','individual','matter','safety','turn','everything','kind','quality','soil','ask','board','buy',
			'development','guard','hold','language','later','main','offer','oil','picture','potential','professional','rather',
			'access','additional','almost','especially','garden','international','lower','management','open','player','range','rate',
			'reason','travel','variety','video','week','above','according','cook','determine','future','site','alternative','demand',
			'ever','exercise','following','image','quickly','special','working','case','cause','coast','probably','security','true',
			'whole','action','age','among','bad','boat','country','dance','exam','excuse','grow','movie','organization','record',
			'result','section','across','already','below','building','mouse','allow','cash','class','clear','dry','easy','emotional',
			'equipment','live','nothing','period','physics','plan','store','tax','analysis','cold','commercial','directly','full',
			'involved','itself','low','old','policy','political','purchase','series','side','subject','supply','therefore','thought',
			'basis','boyfriend','deal','direction','mean','primary','space','strategy','technology','worth','army','camera','fall',
			'freedom','paper','rule','similar','stock','weather','yet','bring','chance','environment','everyone','figure','improve',
			'man','model','necessary','positive','produce','search','source','beginning','child','earth','else','healthy','instance',
			'maintain','month','present','program','spend','talk','truth','upset','begin','chicken','close','creative','design',
			'feature','financial','head','marketing','material','medical','purpose','question','rock','salt','tell','themselves',
			'traditional','university','writing','act','article','birth','car','cost','department','difference','dog','drive','exist',
			'federal','goal','green','late','news','object','scale','sun','support','tend','thus','audience','enjoy','entire','fishing',
			'fit','glad','growth','income','marriage','note','perform','profit','proper','related','remove','rent','return','run','speed',
			'strong','style','throughout','user','war','actual','appropriate','bank','combination','complex','content','craft','due',
			'easily','effective','eventually','exactly','failure','half','inside','meaning','medicine','middle','outside','philosophy',
			'regular','reserve','standard','bus','decide','exchange','eye','fast','fire','identify','independent','leave','original',
			'position','pressure','reach','rest','serve','stress','teacher','watch','wide','advantage','beautiful','benefit','box',
			'charge','communication','complete','continue','frame','issue','limited','night','protect','require','significant','step',
			'successful','unless','active','break','chemistry','cycle','disease','disk','electrical','energy','expensive','face',
			'interested','item','metal','nation','negative','occur','paint','pregnant','review','road','role','room','safe','screen',
			'soup','stay','structure','view','visit','visual','write','wrong','account','advertising','affect','ago','anyone','approach',
			'avoid','ball'
		])

	def randlogin(self):
		return random.choice([
			'idiocyxy','x3ajgnk','rs13xtz','zavzema','AssupR','ummubkt','em_inha','xxthin','lovexxve','nagevol',
			'Prahun','zguren','valent','anonik','Boutibi','mitelem','atomiz','etnolo','ze2ta2c','nakrenu',
			'Scheuc','aefoxw','illowqn','gollwn','aldo92','pasjomny','str_ou','magsle','bybelbo','canalet',
			'sabina','br1234','nagica','trzaladh','nosie','lustrou','nullvek','trissa','heynes2r','j3s2tgk',
			'vises1b','maemoto','ata2lap','britne','ysboobspy','tomaiajl','washau','partie','Math20','Ogulink',
			'pvilla','lobos2j','rhagra','pinaybl','aprilbl','humorn','obtahov','agrafat','Entlerf','BPOws',
			'a2p1op','uchelaf','crmdp','mhuinn','cohitar','teampu','opercu','Ladidu','MirmEr','ronee','erDoll',
			'searahlj','g1intjy','Alpenk','Ektrop','Auswuch','frevel','o1kia','iconhav','est_en','Dipnai',
			'surraS','quotex','otasticvz','quecul','trueblo','nde71','brigida','shwoodrx','dreamfo','klopten',
			'ardalh','su_ers','ayayin1n','glitter','Weanna','masiki','elblogd','einsai5w','Pedale','gbvideo',
			'dragon','hotnewsjt','FoumeV','demagog','vojnik','Sernau0h','luydduuf','orabler','paxopsc','wrmbul',
			'letinoe','lobaret','ladyan','madcow','mallet','Elvisi','tenory','angeli','aber1r','t1ar1c','Runtim',
			'Ticenvi','zagabee','wokux','gestor','rezilce','duizel','ma_uzibx','deedee','pinkch','eerios5g',
			'gsusfr','eekdawnu','konfetx','nemiza','klimopb','ko2r1as','joelle','ferrEe','iijoku','apozeug',
			'previsyh','pension','Gaiarsa','Neuans','burrou','ghsman3l','milenim','unapre','dekunci','Dawudte',
			'smutnyrv','monsmo','Domiblo','oria6z','dodawan','torrent','hatedw','aluhim','BopilkT','oola9j',
			'ventver','Simeoli','beibla','deposa','Farbeim','nijemc','ratelafq','wangel','ia777k0','Galesta',
			'o3mundo','lepido','maTTdre','agotar','nakeds','ilencehd','jothep','paiso1u','sjekteap','globoja',
			'pascut_','despar','elegike','agressz','dwarro','wchild','pomeri','maksill','Scibell','Puncovhh',
			'arturo','onorio8','gmit6m','Briesse','kildrx','stebrce','WedLaye','xiaLabxc','tipiciz','Warburg',
			'Moospad','vavasf','NekOth','throww','crogai','groors','eZoog1v','Hurenbo','fuktigty','raspus',
			'bonkalw','varaul','lemoncl','eansepm','Cabrol6b','fdUYse','Aujume','enzo909','halSboy','envadid',
			'flaGka','slAvenk','Rucmanc','CYsNBYN','CVOK2h','z2jmw','entrica','clumsys','hakess','wimberg','ystormqz',
			'rollrgu','rl31zh','naklapa','Penzify','sxxDyb','aby123','marmote','uloviju','encore','crecian',
			'jetlede','eshorsdr','glockech','aid_e1','spainy','Bouswr','areeCorsm','wingts','ang2009s',
			'miseri','aphyn','xliddox','angel2m','Erartoo','heriaf','kilich','garoxb','deplet','wudabum',
			'o2e1maj','Roulett','ashell','eystar','Trnove','Csato0','betisin','timext','urner6v','lurk_mjk',
			'prvobor','Pekten','agulhoa','bancala','ocotla','st4ie6j','Cohesdps','Jozzino','Eltzetj','edumnR',
			'ogdreoms','tandwer','keberi','konzil','xskall','elujahxa1','Szramo','pinksod','a30084','gargui',
			'diSco','discoze','asigna','DemOren','ueDookqr','yeggmh','b_ilar','zasutim','Volksm','Dirmin','wynwynyh',
			'biAllai','odiblegy','secret','tresuts','insuran','wereka','Varvell','nashina','prelud','eroninl',
			'aturdid','przybi','vedric','visuale','dgare','Anagen','Waldtei','fyllili','parsie','Affefly',
			'temy4','maddi6','mshihi','renaren','Gnevsd','Cerigat','jrpanta','mejican','lanosa','thehul','kstoygw',
			'acard','tulpen','bamazeiz','Gezirph','szmerek','atkilus','USAswk','aveusid','Karftwr','rhen21',
			'Edelhe','sklonit','bbosta','premost','Hentze','chente','xblogg','nebhan','stormde','illich',
			'buDlsn','uilogymk','dyftykxu','custodi','rotace2q','spapos','teodsvi','iskrcal','Iantaf','goriSt',
			'oottewu','pe3r2o','mister','newDig','hmarete','friend','lojanoih','Floress','em_li','feblai',
			'Aramee','Pleldce','rdemx0','turjainj','claire','lascauxbd','bankob','nibris9a','quotei','liciouss',
			'angfer','gwmpas','Oppona','camicoxa','magolen','abgegu','nemirni','Attinsv','Bikinic','hollvi',
			'sz3s2rx','Miraga','droitdu','sagev3','toady2','amrantu','Skactw','Steando','dofadeea','exharac',
			'umerilo','guindar','letopi','sars01','odsiewa','Laxaxi','CorsCoi','phasiw','sebanso','papito','solteroj',
			'webpens','ieroul','pup0soj','Gerault','Dymnkey','peDoffi','Algowne','gorigejn','umnini','rompora',
			'misvan','inchex','conger39','Husckov','minciu','thepook','becknay','Thurne','zasipan','fresalyz',
			'lagosp','kesiCa','emuttog','eddyft','ae2pezi','gebutte','glukoza','Pugljem','pembiu','Partita','unanie',
			'Seekan','mal_nge','AR8oy','van300','Caile9w','imaceph','elmKamfn','_otsant','hakutul','imborn','msgpush',
			'ghiono','Scabbio','Azad4o','espadel','itipara','noid13h','K8CTZAE','j0j0fan','elcalv','oinvitab',
			'izmail','ersatzub','perihel','rovovs','seguico','ll_raw','rhodib','Kandora','ariup3t','Musarje',
			'Kindhar','diarej','su_and','gamesii','krypina','drip21lc','fajansa','Saipan3s','scenar','tubrhr',
			'frakti','oporowi','Galfano','miquelc','asals0k','kuransk','rovito6d','ventepr','e3rumqa','istrebi',
			'treui','atupat','Irrara','goca_p','sintagm','bi1laeh','5pawkf','vaginmw','pasCelc','upcakeok',
			'zeefact','severu','crysenc','matresR','Tyncder','card9z','turdide','gewelna','hinzieh','pegreed',
			'ilydaynw','pazaro','comatt','Wicewoo7','ipicaslj','_ehabyuo','heilias','mediasf','erasie','Doonvat',
			'antanow','luxatsu','discoun','longia','darkdi','zagorze','ffiwdal','remira','Santia','vireki','dukinog',
			'aeast','blogmg','greent','Kompasu','skouro','dekadis','go2r1e','predise','exile2','rishig','loiswan',
			'glingsz','zeggeT','espiran','Paulina','mesmots','blogla','dukeblu','e3100tk','veldua0','Engakyc',
			'anny5','protkan','islamo','WibleDu','mDoobej','marcad','sajaste','codothi','ParlFed','aTarieca',
			'Remorin','Cagnol','doceer','seneVe','me_horm04','encres','letst5k','pus1an','desbard','Eleltyz',
			'rudeja','tAffy','xoxoba','bes15h','1JF6W5','namahac_','dakgras','deeltji','Zanoll','ubervo','alyren',
			'Snulle','Kiestra','wilfred','mong24','Jizba2e','decade','rispiglp','sammieb','Fexwoos','uthiwea',
			'rutelk0','migrad','Garitox0','teleti','mitoman','Bellon','thoirh3','krizoji5','elcabo','pengeve',
			'estivat','propiri','chamuy','amosargen','silver','osmotri','il1blqr','kieuhol','odgojn','mybste',
			'Grabela','laminat','brukke','izr_ci','journa','ldexcogi','dekadam','recarga','musivi','gl0var','aubavaqf',
			'lildrum','magurluv','d_rkogr','ande16pw','ruthie','reapud','Baccian','azizaju','yndisle','niedurn',
			'fre_aky','prynceZ','binnetr','Realduc','cels0','Bleifar','Affeldl','eaps00','caitgoe','srarr6i',
			'skater','pokrov','Llangoe','Armeenj','falq_e','rasierqv','Sarasp','anmelde','Falten','aparen','sur3n',
			'filtra','myesca','peroute','mold_o','Prascaf','Franck','cyllell','klargje','iwapoj2','_ymhell','akaofg',
			'rabanh','Osmundw','nazizm3w','Capuni8c','poseerm','noillio','rmem70','oplugt','szaladh','drpsalk6',
			'nomerom','morneg','Aas_und','Geraunz','Minota','fiRehea','zuwette','Lass_g0','lAinemo','utaineaq',
			'club85uk','sachouu','timelip','oscinm','zaPrek','gudangm','dyemeng','shal_a','zingars','orraL',
			'syNge','cha_araj','perche','moronic','whoLehea','comatab','unauctio','dexorsa','kilLick','ambassad',
			'tro0met','sWingleb','bo_cie','hesitant','model','scanties','taeniac','onset','abridgme','sylvine',
			'nonsubtr','cravat','preserve','rennie','lakiest','jibingly','judges','analyse','sKying','precursi',
			'captivat','unme_ll','moravia','warta','cymotric','oveRast','t_ansdes','prudce','xylograp','vulcanis',
			'fusser','diglot','ratEuSes','jodean','sitatung','nilotic','obelise','unde_rog','hydraog','dampish',
			'brink','ovstir','polymeri','radiopaq','baronize','depew','deductib','hemorRa','abyss','price','selma',
			'poniche','pyrenoid','postvent','keLson','eneReti','uneloped','dahna','soyinka','coCklesh','wilton','chalet',
			'ecsc','corrosiv','cunei','jesselto','therm','houSefly','diacylu','outtrave','dravite','ins0nol','sorrento',
			'lebrun','prEbronz','dextra','noadou','stornoWa','non_iti','leapt','hyphenis','wheeze','scrapper','palki',
			'exp_icat','suboma','incused'
		])

	def randproduct(self):
		return random.choice([
			'jelly','capsicum','valencia','whitefish','bay','candied','runny','bells','worcestershire','hibiscus','jus','herdez',
			'italian','well','grand','fideos','flavoring','sharp','mint','kewra','kasha','fines','romano','pace','bird','boiled',
			'ridged','despelette','coleslaw','saki','heirloom','avocado','furikake','lentil','kasuri','buffalo','stilton','arrowroot',
			'juniper','no-salt-added','bun','pollock','tomato','lard','moulard','pancetta','fennel','capers','aged','jimmies','cotechino',
			'pan','paper','brains','muscadine','baked','coloring','deli','bisquick','curly','gem','smoke','cooking','cookies','herbsaint',
			'brioche','pistachios','flaked','cal','the','mulato','capellini','crumb','color','organic','fat','crystallized','dreamfields',
			'tostada','almond','squirrel','biscotti','pecans','rotisserie','cool','fingers','aminos','lager','rosa','hellmanns','flower',
			'shoulder','peach','fine','caps','marshmallow','scallions','spinach','chiffonade','boiling','rock','pack','oats','chicory','chia',
			'hamburger','bars','pod','uncle','brats','hemp','alaskan','banana','beaters','strong','thai','english','meatballs','ziti',
			'hungarian','bar','kraft','mussels','bottled','less','pastrami','m&ms','tomatoes','snaps','skins','cumin','basil','spear',
			'compressed','creamed','pears','bbq','deviled','sprigs','shell','bushi','bitter','mary','cannellini','campari','grated','porter',
			'satsuma','fillet','ale','onions','drink','mushrooms','rounds','french','beansprouts','speck','superfine','tangelos','shoots','thyme',
			'fritos','almonds','tawny','masoor','jell-o','shortcrust','pillsbury','lychees','chambord','gravy','pockets','porterhouse','blade',
			'cashew','persimmons','smoked','canton','campanelle','sambhar','uncooked','tip','lasagne','olives','slices','violets','cubes','fresca',
			'brewed','risotto','madeira','chayotes','free-range','chipotl','swanson','slice','oysters','parmigiana-reggiano','recaito','saltines',
			'turkei','refried','center-cut','hellmanns','gallo','tonic','northern','hatch','romaine','reduced','baking','sweeten','bibb','orecchiette',
			'broiler-fryers','mullet','chile','chilegarlic','iceberg','kong-style','tradit','kikkoman','oil-cured','hoagie','bicarbonate','salami',
			'flatbread','pecorino','european','maida','boneless','agar','vegetarian','king','fishcake','distilled','dinner','part','goji','chopped',
			'gelatin','roast','microgreens','hushpuppy','methi','juice','rack','beaten','chipotles','champagne','tangzhong','treacle','turkish',
			'paccheri','cornbread','taco','blossoms','ramps','vermouth','nopales','noir','piece','ro-tel','lentils','mirin','curry','bunches','with',
			'free','yuca','lemon-lime','meat','cabernet','tapioca','medium','steel-cut','dry','cornish','eye','extract','quinoa','caramel','knockwurst',
			'chicken-apple','ham','tomatillo','sorghum','hershey','corned','texas','fig','orange','shiso','scrub','fondant','harissa','grouper','silk',
			'tarragon','poha','striped','tortilla','panko','fermented','daniels','frozen','herbed','chablis','monterey','forest','brazil','sandwiches',
			'spare','oil','sucanat','feet','basmati','jumbo','beef','dasti','remoulade','cranberries','hard','licorice','ciabatta','chicken-flavored',
			'callaloo','five','assorted','pot','andouille','dashi','hazelnuts','clams','arugula','drained','duncan','san','chenpi','syd','hens','browning',
			'linguisa','wild','wholemeal','boston','yolks','unsmoked','blanco','liquid','barbecue','pesto','paprika','grapefruit','pasteurized','con',
			'santo','halloumi','rye','gomashio','beaujolais','crumbs','soymilk','stick','bowls','fresh','collards','couscous','flaxseed','pie','seasoned',
			'split','chimichurri','mrs.','saltine','rum','jam','oatmeal','yucca','nut','shiitake','calcium','endive','artichoke','bresaola','spiced',
			'gizzards','taro','wish-bone','steamed','cantaloupe','sugar','string','seltzer','albacore','head','rendered','del','tenderloins','prego',
			'sum','instant','polenta','katsuo','quickcooking','crookneck','peperoncini','emmenthal','perilla','ackee','stir','marjoram','goya','sago',
			'dasheen','single','asafoetida','nero','meal','anjou','grappa','wafer','cranberry','part-skim','confit','warm','ears','clove','traditional',
			'cortland','mixture','tuna','purГ©e','collard','veget','ketchup','moscato','cookie','laughing','apricots','macadamias','tonkatsu','rapeseed',
			'short','cottage','habanero','wheat','peasant','portobello','garland','farms','kosher','non-fat','idaho','leaves','peppers','gruyere','framboise',
			'salted','shelled','groundnut','crumble','masa','hines','wrappers','cannoli','gammon','fleur','hock','quick','rose','butt','maple','bitters',
			'brisket','dolce','rabbit','baileys','fried','pico','bow-tie','marinara','phyllo','cloves','bee','manzanilla','cornmeal','burgundi','seedless',
			'batter','linguica','base','lowfat','shanghai','marcona','nutella','red','gelato','hot','edible','grilled','frisee','chops','fish','artichokes',
			'rub','extra','kaffir','matzos','ronzoni','grass','small','parmigiano-reggiano','crispy','mexican','lily','salmon','loin','crema','dogs','puree',
			'paste','roots','olive','orang','coarse','chard','lasagna','into','peaches','swordfish','burger','fats','club','malted','oranges','florets','relish',
			'browns','cuisine','cupcakes','flowers','schnapps','pink','slivered','bloody','prepar','four','trout','whipped','chee','substitute','giantв„ў',
			'blanched','caciotta','decorating','glass','min','gold','rotelle','jerk','mild','center','hass','filling','bits','soft-boiled','hearts','leaf',
			'chГЁvre','jerusalem','promis','leafy','fromage','canned','veal','ginger','america','strawberry','original','pickles','fatfree','caviar','tenderloin',
			'queso','varnish','cooked','cholula','brussels','sanding','sourdough','hollandaise','picholine','guava','fusilli','pots','ripened','ulek','persian',
			'ragu','splenda','bechamel','medal','precooked','nori','indian','philadelphia','mix','skin','parsley','disco','sprouts','seafood','snapper','parts',
			'rolls','calabaza','minicub','prawn','farmer','bones','bamboo','kirsch','cornflour','oxtails','slab','chianti','turkey','confectioners','raw',
			'flounder','lite','dogfish','stout','leftover','hen','bawang','plus','fashioned','anardana','korean','links','ouzo','nu-salt','shichimi','seville',
			'penne','ranch','daal','brand','breadcrumbs','pate','aka','for','white','roll','beets','zinfandel','rutabaga','cayenne','extra-lean','channa','chili',
			'laurel','croissants','dark','drumstick','chapatti','gras','kahlГєa','tartlet','prebaked','sel','halves','naan','sage','marrow','preserves','azuki',
			'chapati','masala','erythritol','brine-cured','shredded','shank','moong','picante','biscuit','tahini','ritz','shaved','curing','cured','mellow','low',
			'butter','fajita','stuffing','pastis','kinchay','bananas','refrigerated','chestnut','spelt','provence','merguez','canola','non','lop','daisy','paddles',
			'cardamom','fen','hocks','domaine','sun','verts','mitsuba','sazon','boiler','knudsen','packed','kataifi','croutons','kale','mezcal','sun-dried','mission',
			'grill','brown','pear','buckwheat','shavings','hog','annatto','fries','crГЁme','sausages','pasilla','ditalini','chips','tomato-and-basil','pepperidge',
			'beans','bacon','sherry','pudding','palm','yum','round','fraise','chive','medallions','heads','fudge','elbow','zesty','sesame','popsicle','rib-eye',
			'soften','dal','greens','gluten','mochi','gherkins','smith','granny','premium','almondmilk','calamata','homestyl','dende','alfredostyle','regular',
			'pinipig','asafetida','molasses','shellfish','plain','mandarin','cow','equal','anejo','nugget','lapsang','simply','merluza','montreal','tri-tip','eggs',
			'maggi','negro','vienna','fryer','imo','granular','turtle','leche','doubanjiang','maitake','bran','broad','soursop','cherrystone','rome','mentaiko',
			'avocados','armagnac','potatoes','island','duxelles','posole','oyster','chillies','blossom','pasoв„ў','vodka','plums','lacinato','marnier','raising',
			'silken','safflower','blueberry','style','bramley','grey','tilapia','teas','dubliner','roux','crumbled','arthur','citron','irish','pimento','piecrusts',
			'escarole','jambalaya','winter','gouda','taglierini','sunflower','menthe','bulk','mascarpone','lamb','mortadella','barilla','gremolata','semi','cassia',
			'sec','mahi','escargot','skate','kidnei','converted','liquor','mexicana','olivada','shrimp','salt','success','day','chex','piloncillo','blend','chutney',
			'konbu','japanese','vietnamese','chana','limeade','harina','slaw','anchovies','carnitas','crab','toppings','dates','canela','thick-cut','uncook','suet',
			'fleshed','pinto','sato','dress','borlotti','nilla','kitchen','broth','chow','vanilla','turmeric','recipe','reduc','corkscrew','stickers','lemon','range',
			'padron','lemongrass','serrano','soybean','kernel','figs','cream','pickle','puff','giblet','mazola','york','classic','prawns','stone-ground','capicola',
			'dillweed','clarified','napa','nigella','sorrel','peanut','lambs','mexico','all','diced','wax','tamarind','jackfruit','sundae','vegetable','sea','pollen',
			'salsa','asparagus','mahimahi','balls','tandoori','grain','aleppo','cola-flavored','gumdrops','balm','pecan','tostadas','leg','soba','nutritional','cannelloni',
			'dri','country-style','dzem','passion','yams','dipping','manioc','stems','lovage','taleggio','pompeian','miniature','watercress','nutmeg','lean','cane','kim',
			'lan','pepitas','straw','jarlsberg','bean','germ','garam','green','tails','savory','double-dark','pineapple','panela','burgundy','nuoc','muffin','semolina',
			'peanuts','semi-sweet','saba','jalapeno','low-fat','carcass','padano','syrup','galangal','ducklings','chees','prosciutto','pimenton','skinless','foster',
			'multipurpose','flowerets','medium-grain','surimi','egg','horseradish','dream','table','flanken','herbes','nen','nutmegs','loaf','thousand','madras','navy',
			'okra','button','macaroni','wakame','choi','flax','crabmeat','parmesan','miracle','shirataki','ghee','colorado','frosting','konnyaku','praline','peppercorns',
			'doenzang','mixed','fry','glaze','loaves','sandwich','starchy','starch','mango','seca','crust','peas','malbec','hominy','shuck','alfalfa','mountain','mackerel',
			'yardlong','anchovy','apricot','wildflower','best','liqueur','herbal','calorie','gorgonzola','rosemary','acid','sprite','crumbles','root','lobster','bengal',
			'dog','cepe','jicama','walnut','young','pancit','pea','yuba','usukuchi','tortillas','pandanus','sumac','cuts','pressed','cook','sundried','perfect','sardines',
			'chop','treviso','hazelnut','coriander','husks','cava','krachai','unsulphured','yellowtail','raspberries','gran','eggplant','szu','field','peppered','morel',
			'amaretto','choy','garlic','cutlets','boil','kielbasa','cavatappi','chickpea','havarti','massaman','sultana','pumpernickel','honeydew','plantains','kiwi',
			'wheels','corn-on-the-cob','enokitake','asadero','sambal','hothouse','doughs','key','cassis','cider','yakisoba','pГўte','fava','pound','crescent','chinkiang',
			'old-fashioned','segments','bens','kettle','yuzu','bulgur','devils','urad','buttercream','shortening','dash','bragg','calvados','hong','edam','hand','monkfish',
			'pepe','firm','hint','franks','cavolo','sevruga','beet','chilli','imitation','butter-flavored','quail','jack','nama','glace','cherries','acai','rins','kelp',
			'papaya','adzuki','brandy','empanada','pumpkin','fronds','breast','large','sweetened','flavor','rhubarb','adobo','skin-on','soi','baton','house','truffles',
			'golden','vidalia','rotel','sour','taiwanese','sansho','plum','moisture','jeera','season','whipping','black-eyed','oregano','flake','whip','genoise','linguine'
		])

	def randendpunct(self):
		return random.choice(['.','!','?','!!!','?!'])

	def randallergen(self):
		select = random.randrange(0, 10)
		if select < 2:
			return self.randword()
		return self.randproduct()

	def randingredients(self, minsize=3, maxsize=10, delim=", "):
		result = self.randproduct()
		rnd = random.randrange(minsize, maxsize)
		for i in range(rnd):
			result += delim
			result += self.randproduct()
		return result

	def randuser(self, flag, randlen):
		login = uuid.uuid4().hex[:randlen]
		passlen = random.randrange(6,10)
		password = uuid.uuid4().hex[:passlen]
		select = random.randrange(0, 10)
		if select < 4:
			allergens = [flag]
		elif select < 8:
			allergens = [self.randallergen(), flag]
		else:
			allergens = [flag, self.randallergen(), self.randallergen()]
		return {'login':self.randlogin() + login, 'pass':password, 'allergens':allergens}

	def semiranduser(self, flag, randlen):
		login = uuid.uuid4().hex[:randlen]
		passlen = random.randrange(6,10)
		password = uuid.uuid4().hex[:passlen]
		allergens = [flag]
		select = random.randrange(0, 10)
		if select < 4:
			allergens = [flag, self.randallergen()]
		elif select < 8:
			allergens = [self.randallergen(), flag]
		return {'login':'FoodBot 0x' + login, 'pass':password, 'allergens': allergens}

	#################
	#     CHECK     #
	#################
	def check(self, addr):
		s = self.session(addr)

		result = self.sget(s, addr, '/')
		if not result or len(result) == 0:
			print('get / failed')
			return EXITCODE_MUMBLE

		return EXITCODE_OK

	#################
	#      GET      #
	#################
	def get(self, addr, flag_id, flag, vuln):
		if vuln == 1:
			return self.get1(addr, flag_id, flag)
		else:
			return self.get2(addr, flag_id, flag)

	##################
	#      GET 1     #
	##################
	def get1(self, addr, flag_id, flag):
		s = self.session(addr)

		parts = flag_id.split(':', 2)
		user = {'login':parts[0], 'pass':parts[1]}

		self.debug(user)

		result = self.sget(s, addr, '/')
		if not result or len(result) == 0:
			print('get / failed')
			return EXITCODE_MUMBLE

		csrf_token = s.cookies.get('csrf-token')

		result = self.spost(s, addr, '/signin', [
			('login', user['login']),
			('pass', user['pass']),
			('csrf-token', csrf_token)])
		if not result or result.find(flag) < 0:
			print('flag not found')
			return EXITCODE_CORRUPT

		return EXITCODE_OK

	##################
	#      GET 2     #
	##################
	def get2(self, addr, flag_id, flag):
		s = self.session(addr)

		result = self.sget(s, addr, '/get?id=' + flag_id)
		if result.find(flag) < 0:
			print('flag not found')
			return EXITCODE_CORRUPT

		return EXITCODE_OK

	###################
	#      PUT        #
	###################
	def put(self, addr, flag_id, flag, vuln):
		if vuln == 1:
			return self.put1(addr, flag_id, flag)
		else:
			return self.put2(addr, flag_id, flag)

	###################
	#      PUT 1      #
	###################
	def put1(self, addr, flag_id, flag):
		s = self.session(addr)

		result = self.sget(s, addr, '/')
		if not result or len(result) == 0:
			print('get / failed')
			return EXITCODE_MUMBLE

		csrf_token = s.cookies.get('csrf-token')
		#cookies_string = "; ".join([str(key) + "=" + str(val) for key, val in s.cookies.items()])

		time.sleep(random.random())

		user = self.semiranduser(flag, 8)
		self.debug(user)

		ws = DummyClient('ws://{}:{}/'.format(addr, WSPORT), headers=[
			#('Origin', 'http://{}:{}'.format(addr, PORT)),
			('User-Agent', self.randua())])
		try:
			ws.daemon = True
			ws.setargs(None, user['login'])
			ws.connect()

		except WebSocketException:
			self.debug(traceback.format_exc())
			print('websocket connect failed')
			return EXITCODE_MUMBLE

		else:
			if not OPEN.wait(3):
				print('await hello failed')
				return EXITCODE_MUMBLE

			time.sleep(3 + random.randrange(1, 4) + random.random())

			result = self.spost(s, addr, '/signup', [
				('csrf-token', csrf_token),
				('login', user['login']),
				('pass', user['pass']),
				('allergen', ", ".join(user['allergens']))])
			#if not result or result.get('about') != flag:
			#	print('registration failed')
			#	return EXITCODE_MUMBLE

			if not DONE.wait(3):
				print('await message failed')
				return EXITCODE_MUMBLE

			title = self.randingredients(1, 4, " ")
			msg = [('title', title), ('ingredients', flag + ', ' + self.randingredients()), ('csrf-token', csrf_token)]

			result = self.spost(s, addr, '/put', msg)
			if not result:
				print('send msg failed')
				return EXITCODE_MUMBLE

			print('{}:{}'.format(user['login'], user['pass']))
			return EXITCODE_OK

		finally:
			try:
				ws.close()
			except:
				self.debug('WebSocket close failed')

	#######################################
	def reguser(self, s, addr, csrf_token, flag):
		user = self.randuser(flag, 2)
		for i in range(0, 3):
			try:
				result = self.spost(s, addr, '/signup', [
					('login', user['login']),
					('pass', user['pass']),
					('allergen', ", ".join(user['allergens'])),
					('csrf-token', csrf_token)])
				break

			except HttpWebException as e:
				self.debug('Auth: ' + str(e.value))
				if e.value == 409 and i < 2:
					user = self.randuser(flag, i * 5)
				else:
					raise
		return user

	###################
	#      PUT 2      #
	###################
	def put2(self, addr, flag_id, flag):
		s2 = self.session(addr)

		result = self.sget(s2, addr, '/')
		if not result or len(result) == 0:
			print('get / failed')
			return EXITCODE_MUMBLE

		csrf_token2 = s2.cookies.get("csrf-token")

		user2 = self.reguser(s2, addr, csrf_token2, flag)
		self.debug('User (ws): ' + str(user2))

		cookies_string = "; ".join([str(key) + "=" + str(val) for key, val in s2.cookies.items()])

		time.sleep(random.random())

		s = self.session(addr)

		result = self.sget(s, addr, '/')
		if not result or len(result) == 0:
			print('get / failed')
			return EXITCODE_MUMBLE

		csrf_token = s.cookies.get("csrf-token")

		user = self.reguser(s, addr, csrf_token, self.randallergen())
		self.debug('User (put): ' + str(user))

		#user = self.randuser(4)
		#result = self.spost(s, addr, '/auth', [('csrf-token', csrf_token), ('login', user['login']), ('pass', user['pass'])])
		#if not result or len(result) == 0:
		#	print('register user failed')
		#	return EXITCODE_MUMBLE

		time.sleep(random.random())

		title = self.randingredients(1, 4, " ")
		msg = [('title', title), ('ingredients', flag + ', ' + self.randingredients()), ('csrf-token', csrf_token)]

		ws = DummyClient('ws://{}:{}/'.format(addr, WSPORT), headers=[
			#('Origin', 'http://{}:{}'.format(addr, PORT)),
			('User-Agent', s2.headers['User-Agent']),
			('Cookie', cookies_string)])
		try:
			ws.daemon = True
			ws.setargs(title, flag)
			ws.connect()

		except WebSocketException:
			self.debug(traceback.format_exc())
			print('websocket connect failed')
			return EXITCODE_MUMBLE

		else:
			if not OPEN.wait(3):
				print('await hello failed')
				return EXITCODE_MUMBLE

			self.debug(msg)

			time.sleep(3 + random.randrange(1, 4) + random.random())

			result = self.spost(s, addr, '/put', msg)
			if not result:
				print('send msg failed')
				return EXITCODE_MUMBLE

			id = result

			if not DONE.wait(3):
				print('await message failed')
				return EXITCODE_MUMBLE

			print(id)
			return EXITCODE_OK

		finally:
			try:
				ws.close()
			except:
				self.debug('WebSocket close failed')

Checker().run()

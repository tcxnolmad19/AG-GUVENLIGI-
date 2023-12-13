`                      `**AÇIK KAYNAK ARAÇLARLA AĞ GÜVENLİĞİ DÖNEM ÖDEVİ**

`                                     `**Ağ Güvenliği Uygulamaları ve Araçları**

**1.Güvenlik Duvarları (Firewalls**

**2.Antivirüs ve Antimalware Yazılımları**

**3. İçerik Filtreleme Araçları**

**4. Güvenlik Bilgi ve Olay Yönetimi (SIEM) Araçları**

**5. Güvenlik Analiz Araçları**

**6. Ağ İzleme ve İstihbarat Araçları(IDS/IPS)**

**7. Kimlik Doğrulama ve Erişim Kontrolü Araçları**



**1.Güvenlik Duvarları (Firewalls:** Güvenlik duvarları (firewalls), bilgisayar ağları veya bilgisayar sistemleri arasında iletişimi denetlemek, filtrelemek ve korumak için kullanılan bir güvenlik önlemidir. Temel olarak, güvenlik duvarları, istenmeyen erişimleri engelleyerek ağ trafiğini izler ve denetler. 

`       `Uç Nokta (Host) Tabanlı Firewall Örnekleri: Windows Defender Firewall, Comodo Firewall,       

`       `AĞ TABANLI FİREWALLS:

`     `**Cisco ASA (Adaptive Security Appliance):** Adaptive Security Appliance anlamına gelen Cisco ASA, Cisco Systems tarafından geliştirilen bir güvenlik cihazıdır. Güvenlik duvarı, VPN (Sanal Özel Ağ) yoğunlaştırıcısı ve izinsiz giriş önleme sistemi (IPS) olarak işlev görür. ASA, güvenlik duvarı özelliklerini, ağ antivirüsünü, VPN'yi ve izinsiz giriş önlemeyi tek bir donanım cihazında veya sanal cihazda birleştirir.

Cisco ASA, Siteden Siteye VPN ve Uzaktan Erişim VPN'i gibi çeşitli VPN teknolojilerini destekler. İnternet gibi genel ağlar üzerinden uzak konumlar veya bireysel kullanıcılar ile kurumsal ağ arasında güvenli iletişim sağlar.

`       `**Palo Alto Networks Güvenlik Duvarı:** Palo Alto Networks Güvenlik Duvarı, ağ güvenliği ve kablo bağlantısı kontrolü konusunda ileri düzeyde özellikler sunar. Özellikle ayarlar ve büyük ayarlama ağları için tasarlanmış olan bu çözüm, genellikle bir dizi gelişmiş tehdit savunma özelliği sunmasıyla tercih edilir. Platform, sürekli olarak tehditleri analiz eder, tespit eder ve engellerken aynı zamanda yönetim ve raporlama kolaylığı sağlar.



İçerik temelinde saklanan özellikler ile istenmeyen web sitelerine, kategorilere veya belirli içerik türlerine erişimini engeller. Saldırı imzalarını tanımlama, saldırıları engelleme ve saldırı girişimlerini tespit etme yeteneğine sahiptir.

`       `**Check Point Firewall:** Check Point Firewall, Check Point Software Technologies'in ürettiği bir güvenlik duvarı çözümüdür. Check Point Firewall, genellikle büyük ölçekli kuruluşlar, kurumsal ağlar ve veri merkezleri için tasarlanmıştır. Check Point'in güvenlik duvarı çözümleri, kapsamlı güvenlik özellikleri sunarken aynı zamanda yönetim kolaylığı ve geniş raporlama yetenekleri ile bilinir. Ayrıca, Check Point'in sunduğu farklı modeller ve ek özellikler, farklı ihtiyaçları karşılamak üzere esneklik sağlar.

`       `**Fortinet FortiGate:** Fortinet FortiGate, Fortinet şirketinin ürettiği bir güvenlik duvarı ve ağ güvenliği platformudur. Fortinet FortiGate, çeşitli model ve özelliklerde sunulan modüler bir yapıya sahiptir, böylece farklı işletmelerin ihtiyaçlarına uygun ölçekte ve gereksinimlerine göre yapılandırılabilir. FortiGate'in sunduğu kapsamlı güvenlik özellikleri, genellikle büyük ve orta ölçekli kuruluşlar tarafından tercih edilir. Aynı zamanda, Fortinet'in entegre edilmiş tehdit istihbaratı ve güvenlik hizmetleri ile bilinir. Bu hizmetler, sürekli olarak güncellenen tehdit veritabanları ve imza güncellemeleri gibi güvenlik duvarının etkinliğini artırmak için ek katmanlar sağlar.

`       `**Open-source Güvenlik Duvarları**

`   `**Pfsence:** pfSense, çok çeşitli ağ güvenliği özellikleri sağlamak üzere tasarlanmış, FreeBSD'yi temel alan açık kaynaklı bir güvenlik duvarı ve yönlendirici yazılım dağıtımıdır. Güvenlik duvarı, yönlendirme, VPN, trafik şekillendirme ve daha fazlasını içeren birçok özellik sunması, onu özellikle küçük ve orta ölçekli işletmelerde, eğitim kurumlarında ve ev ağlarında ağların güvenliğini sağlamak ve yönetmek için popüler bir seçim haline getiriyor.

`    `**Pfsense Teknik Özellikleri Nelerdir ?**

`     `**Güvenlik Duvarı**
`     `• Kaynak veya Hedef IP, Protokol, kaynak veya hedef portal(UDP/TCP trafiği için) göre filtreleme.
`     `• İşletim sistemine göre paketlerin geçişine izin verebilme veya engelleme.
`    `• Her kural için kayıt tutma ya da tutmama.
`    `• Her kural için politika tabanlı yönlendirme .(Özellikle yük dengeleme, failover, çoklu geniş ağ bağlantısı yönetimi)    

`     `• IP, ağ veya portların Alias sistemi kullanılarak gruplanabilmesi.
`     `• Transparan 2. katmanda güvenlik duvarı uygulayabilme.
`     `• Paket normalleştirme .(Normalization)
# `    `**Pfsense ile neler yapabiliriz ?**
- Ağınızdaki kullanıcıların erişebilecekleri sayfaları kısıtlayabilir veya engelleyebilirsiniz.
- Kullanıcılarınızın ziyaret ettikleri sayfaları detaylı tarih damgasıyla kayıt altına alabilirsiniz.[Log Kaydı]
- Süreli kısıtlamalar yapabilirsiniz.
- İstediğiniz uygulamaları engelleyebilirsiniz.
- Kategoriler belirleyerek kısıtlama yapabiliriz.(Örneğin; Oyun siteleri,Forumlar,download siteleri,pornografik içerikli siteler vb.)
- Kullanıcılarda kategorilere ayrılarak kısıtlamalar yapılabilir.(Örneğin; Öğrenciler,öğretmenler,personel,muhasebe vb.)
- Kullanıcılara belirlenen kullanıcı adı ve parola bilgileri ile internet erişimlerine izin verilebilir.Böylece wifi ağınızın parola koruması olmasa bile internete kimse erişemez.

`       `**OPNsense:** pfSense'in bir türevi olan OPNsense, aynı temel teknolojiyi kullanarak geliştirilmiştir. Çoğu pfSense özelliğine sahiptir, ancak farklı bir arayüz ve bazı ek özellikler sunar.

`      `**IPFire:** Linux tabanlı bir güvenlik duvarı ve router çözümüdür. Modüler yapısı, kullanıcı dostu arayüzü ve VPN, Intrusion Detection System (IDS), web proxy gibi özellikleriyle dikkat çeker.

`      `**Untangle:** Açık kaynak kodlu bir temel üzerine inşa edilmiş ticari bir güvenlik platformudur. Ücretsiz bir sürümü bulunmakla birlikte, daha fazla özellik ve destek için ücretli sürümler de sunar. Untangle, web filtreleme, VPN, firewall, antivirüs, spam filtreleme gibi özellikleri içerir.

**2.Antivirüs ve Antimalware Yazılımları:** Antivirüs ve antimalware yazılımları, bilgisayarların ve dijital cihazların kötü amaçlı yazılımlardan korunmasına yardımcı olan programlardır. Bunlar, bilgisayar virüsleri, kötü niyetli yazılımlar, casus yazılımlar, solucanlar, truva atları gibi zararlı yazılımların tespit edilmesi, engellenmesi veya temizlenmesi için tasarlanmıştır.

`      `**Antivirüs Yazılım Örnekleri:**

`    `**Norton Antivirus:** Symantec tarafından geliştirilen bir antivirüs yazılımıdır. Gerçek zamanlı koruma, web koruması, e-posta koruması ve otomatik güncellemeler gibi özellikler sunar.

`    `**McAfee Antivirus:** Intel Security (eski adıyla McAfee Inc.) tarafından geliştirilmiştir. Virüs taraması, web koruması, güvenli arama ve dosya şifreleme gibi özellikleri vardır.

`   `**Avast Antivirus:** Ücretsiz ve ücretli sürümleri bulunan popüler bir antivirüs yazılımıdır. Gerçek zamanlı koruma, ağ güvenliği, çevrimdışı çalışma modu ve güvenli tarayıcı gibi özellikler sunar.

`   `**AVG Antivirus:** Avast tarafından satın alınmış olan AVG, virüs taraması, web koruması, e-posta koruması ve dosya şifreleme gibi temel özelliklere sahip bir antivirüs 
**
`     `programıdır.

`    `**Bitdefender Antivirus:** Güçlü virüs tarama özellikleri, web filtreleme, fidye yazılımı koruması ve çevrimdışı çalışma modu gibi özelliklerle bilinen bir antivirüs programıdır.

`     `**Kaspersky Antivirus:** Kaspersky Lab tarafından geliştirilen bir antivirüs yazılımıdır. Güvenilir tarama, web koruması, e-posta filtreleme ve otomatik güncellemeler sunar.

**Antimalware Yazılım Örnekleri:**

`     `**Malwarebytes:** Bilgisayarları kötü amaçlı yazılımlardan korumak için tasarlanmış popüler bir antimalware yazılımıdır. Casus yazılımlar, trojanlar, solucanlar ve diğer zararlı yazılımların tespit edilmesi ve temizlenmesi için kullanılır.

`    `**Ad-Aware:** Lavasoft tarafından geliştirilen bir antimalware yazılımıdır. Bilgisayar virüsleri, casus yazılımlar, trojanlar ve diğer kötü niyetli yazılımlara karşı koruma sağlar.

`    `**Spybot - Search & Destroy:** Zararlı yazılımları tespit etmek ve temizlemek için     kullanılan bir antimalware yazılımıdır. Casus yazılımlar, reklam yazılımları ve diğer potansiyel tehditleri algılar.  

`    `**HitmanPro:** Bulut tabanlı bir antimalware çözümüdür. Bilgisayarın kötü niyetli yazılımlardan temizlenmesi için kullanılır ve diğer antivirüs programlarıyla birlikte kullanılabilir.

`     `**SUPERAntiSpyware:** Casus yazılımları, trojanları, solucanları ve diğer zararlı yazılımları algılamak ve temizlemek için tasarlanmış bir antimalware yazılımıdır.

**3. İçerik Filtreleme Araçları:** İçerik filtreleme araçları, internet erişimini denetlemek ve belirli içeriklerin erişimini engellemek veya kısıtlamak için kullanılan yazılım veya donanım tabanlı çözümlerdir. Bu araçlar genellikle ağlarda, iş yerlerinde, eğitim kurumlarında veya ev ortamlarında kullanılır.

`      `**Web Filtreleme Proxy Sunucuları:** Squid, DansGuardian ve CCProxy gibi web proxy sunucuları, ağ trafiğini kontrol eder ve belirli web sitelerine erişimi engellemek veya izin vermek için kullanılır.

`     `**DNS Tabanlı Filtreleme Çözümleri:** OpenDNS, CleanBrowsing ve Norton ConnectSafe gibi DNS tabanlı filtreleme hizmetleri, kullanıcıların belirli web sitelerine erişimini engelleyebilir veya kısıtlayabilir.

`        `**Uygulama ve İçerik Kontrolü Yazılımları:** Net Nanny, Qustodio, Norton Family gibi yazılımlar, ebeveynlerin çocuklarının internet erişimini yönetmelerine olanak tanır. Belirli içerik kategorilerini engelleyebilir, belirli uygulamaların kullanımını sınırlayabilir veya belirli zaman dilimlerinde internet erişimini durdurabilir.

`        `**Kurumsal Güvenlik Duvarları:** Check Point, Fortinet, Palo Alto Networks gibi kurumsal güvenlik duvarları, içerik filtreleme özelliklerini bünyelerinde barındırarak, kuruluşların ağ trafiğini kontrol etmelerine ve belirli içeriklerin erişimini yönetmelerine olanak tanır.

**4. Güvenlik Bilgi ve Olay Yönetimi (SIEM) Araçları:** Güvenlik Bilgi ve Olay Yönetimi (SIEM), bir organizasyonun veya kuruluşun bilgi teknolojisi altyapısında meydana gelen olayları toplamak, analiz etmek, gerçek zamanlı olarak izlemek ve güvenlik olaylarına karşı tepki vermek için kullanılan bir yazılım ve/veya donanım sistemidir.

SIEM, tüm veri kaynakları tarafından oluşturulan olay günlüklerini ve günlük verileri toplayarak çalışır. Kullanıcılar, sunucular, ağ cihazları, IP’ler, uygulamalar ve güvenlik duvarları, bu olay günlüklerini gerçek amaçlar için birleştirmek, tanımlamak ve kategorilere ayırmak için tek bir merkezi sistemde toplanır. Olay günlükleri esasen tüm etkinliklerin, hataların, bilgi mesajlarının ve uyarıların bir kaydıdır. Başarısız oturum açmalardan, kötü amaçlı yazılım etkinliklerine kadar her şeyi içerebilir ya da bir işletmenin altyapısında tam gözlemlenebilirlik elde ederek olayları, kullanıcı etkinliğini ve olası tehditleri tespit edebilir.

`       `**Splunk:** Geniş ölçekte veri analizi ve güvenlik olay yönetimi için kullanılan Splunk, güvenlik bilgisi ve olayları toplar, analiz eder ve raporlar. Gerçek zamanlı izleme, olaylar arası ilişki analizi ve tehdit tespiti gibi özellikleri bulunur.

`      `**IBM QRadar:** IBM'in SIEM platformu olan QRadar, ağ güvenliği için geniş kapsamlı bir çözümdür. Logları toplar, analiz eder, anormal faaliyetleri izler ve tehditleri tespit eder.

`      `**LogRhythm:** LogRhythm, log toplama, derin analiz, tehdit zekası entegrasyonu ve olaylara yanıt gibi SIEM özelliklerini içeren bir platformdur. Güvenlik olaylarını izler ve sınıflandırır.

`     `**SolarWinds Security Event Manager (SEM):** SolarWinds SEM, güvenlik olaylarına karşı izleme ve yanıtlama yeteneklerine sahip bir SIEM çözümüdür. Logları toplar, analiz eder ve tehditleri tespit eder.

`     `**ArcSight:** Hewlett Packard Enterprise (HPE) tarafından geliştirilen ArcSight, büyük ölçekli kuruluşlar için olay yönetimi ve güvenlik bilgisi analizi sunan bir platformdur.

`    `**AlienVault USM (Unified Security Management):** AlienVault USM, güvenlik bilgisi ve olay yönetimi için birleşik bir platform sunar. Tehtitlerin tespiti, log yönetimi ve güvenlik olaylarının izlenmesi gibi özelliklere sahiptir.



**5. Güvenlik Analiz Araçları:** Güvenlik analiz araçları, bir organizasyonun veya sistemlerin güvenliğini değerlendirmek, tehditleri tespit etmek, güvenlik açıklarını belirlemek ve uygun önlemleri almak için kullanılan çeşitli yazılım ve araçlardır. Bu araçlar, güvenlik olaylarını izlemek, analiz etmek ve yanıtlamak için çeşitli özelliklere ve yeteneklere sahiptir.

`      `**Nessus**:** Nessus, fiziksel taramalar ve zafiyet analizleri için kullanılan bir güvenlik aracıdır. White-Box Penetration(Sızma Testi) testinde kullanılır. Üzerinde desteklenen çoklu platform ağı ve ana güvenlik açığı tarayıcı sunucusudur.

- Server : Windows, Linux, UNIX, Mac
- Client : WEB Tabanlı ve Mobil ( IOS,Android )

Oluşturulacak tarama profiline göre network veya belirli hostlar taranıp güvenlik açıkları keşfedilebilir. Nessus, rekabetçi çözümler, OS taramaları, ağ aygıtları, veritabanları, web sunucuları ve güvenlik açıklarını tehditler ve uyumluluk ihlalleri için kritik altyapıdan daha fazla teknolojiyi desteklemektedir. Nessus Professional, varlık bulma, yapılandırma denetimi, hedef profilleme, kötü amaçlı yazılım tespiti, hassas veri bulma gibi özellikleri barındırmaktadır.

`       `**Snort:**  Snort, şu anda Cisco'nun bir parçası olan Sourcefire tarafından geliştirilen açık kaynaklı bir ağ saldırı tespit sistemi (NIDS) ve izinsiz giriş önleme sistemidir (IPS). IP ağlarında gerçek zamanlı trafik analizi ve paket kaydı için yaygın olarak kullanılır.

Snort'un temel özellikleri şunları içerir:

1. **Paket İncelemesi:** Snort, ağ trafiğini gerçek zamanlı olarak inceler ve paketleri bilinen güvenlik açıkları, saldırı imzaları ve şüpheli kalıplardan oluşan bir veritabanına göre analiz edebilir.
1. **Kural Tabanlı Tespit:** Bilinen tehditlerin veya saldırı modellerinin protokollerini, trafik türlerini ve imzalarını tanımlamak için kurallara dayalı bir dil kullanır. Kullanıcılar, belirli ağ etkinliği türlerini tespit etmek ve bunlara yanıt vermek için özel kurallar oluşturabilir veya mevcut kuralları kullanabilir.
1. **Esnek Dağıtım:** Snort, IPS (İzinsiz Giriş Önleme Sistemi) yetenekleri için satır içi mod veya IDS (İzinsiz Giriş Tespit Sistemi) amaçları için pasif mod da dahil olmak üzere çeşitli ağ mimarilerinde dağıtılabilir; burada trafiği engellemeden potansiyel tehditleri algılar ve günlüğe kaydeder.
1. **Protokol Analizi:** TCP/IP, UDP, HTTP, FTP, SMTP, DNS ve diğerleri dahil olmak üzere çok çeşitli ağ protokollerini ve uygulamalarını analiz edebilir.
1. **Uyarı ve Günlük Kaydı:** Snort, şüpheli veya potansiyel olarak kötü amaçlı etkinlik tespit ettiğinde uyarılar ve günlükler oluşturarak, tespit edilen tehdidin doğası, kaynak ve hedef adresleri ve diğer ilgili bilgiler hakkında ayrıntılar sağlar.
1. **Topluluk Kuralları ve Güncellemeler:** Snort, algılama kurallarını sürekli olarak geliştiren ve paylaşan, sistemi ortaya çıkan tehditler ve güvenlik açıklarına karşı güncel tutan büyük bir topluluktan yararlanır.

Snort genellikle kapsamlı bir ağ güvenliği stratejisinin parçası olarak kullanılır ve ağ yöneticilerinin ve güvenlik profesyonellerinin ağ trafiğini olası güvenlik ihlalleri, saldırılar veya politika ihlallerine karşı izlemesine olanak tanır. Ağ etkinliklerinin görünürlüğünü sağlar ve güvenlik olaylarının tanımlanmasına ve bunlara yanıt verilmesine yardımcı olur.

`     `**Security Onion:** Ağ güvenlik izleme ve analizi için bir platformdur. Wireshark, Snort, Suricata, Zeek gibi araçların bir araya getirilmesiyle ağ parçalarını izler ve güvenlik olaylarını analiz eder.


**Metasploit** :Metasploit, güvenlik profesyonellerinin, araştırmacıların ve etik bilgisayar korsanlarının sistemlerin ve ağların güvenlik durumunu değerlendirmesine ve doğrulamasına yardımcı olan güçlü ve yaygın olarak kullanılan bir sızma testi çerçevesidir. Rapid7 tarafından geliştirilen Metasploit, güvenlik açıklarından yararlanmak, veriler oluşturmak ve güvenlik değerlendirmeleri yürütmek için bir dizi araç ve kaynak sağlar.

Metasploit'in temel bileşenleri ve özellikleri şunları içerir:

1. **Exploitation Framework:** Metasploit, çeşitli sistem ve uygulamalardaki güvenlik açıklarını tanımlamak ve yararlanmak için kullanılabilecek geniş bir istismar, yük ve yardımcı modül veritabanı sunar.
1. **Yük Oluşturma:** Başarılı bir kullanımdan sonra hedeflenen sistemlere dağıtılmak üzere özelleştirilmiş yüklerin oluşturulmasına olanak tanır. Bu veriler, kullanım sonrası faaliyetler için kabuk kodu, ters kabuklar veya diğer kötü amaçlı kod türlerini içerebilir.
1. **Kullanım Sonrası Modüller:** Bir sistem tehlikeye girdiğinde Metasploit, bilgi toplama, diğer sistemlere geçiş, ayrıcalıkları yükseltme veya erişimi sürdürme gibi çeşitli istismar sonrası etkinlikleri gerçekleştirmek için modüller sağlar.
1. **Entegrasyon ve Otomasyon:** Metasploit, komut dosyaları ve API'ler aracılığıyla daha büyük güvenlik testi iş akışlarına ve otomatikleştirilmiş süreçlere entegre edilebilir, böylece verimli ve tekrarlanabilir test prosedürleri sağlanır.
1. **Topluluk ve Güncellemeler:** Sürekli olarak yeni güvenlik açıkları, yükler ve modüller geliştiren ve çerçeveyi en son güvenlik açıkları ve teknikleriyle güncel tutan geniş bir katkıda bulunanlar topluluğundan yararlanır.
1. **Exploit Geliştirme:** İleri düzey kullanıcılar, Metasploit'in istismar geliştirme, test etme ve doğrulama yeteneklerinden yararlanarak güvenlik açıklarının keşfedilmesine ve iyileştirilmesine yardımcı olabilir.

Kali Linux üzerinde bulunan [hashtag#Metasploit](https://www.linkedin.com/feed/hashtag/?keywords=metasploit) Framework terminal üzerinde çalıştırmak için **msfconsole** komutu kullanılır.

**db\_status :** Veri tabanı bağlantı kontrolü.  

**version :** versiyon kontrolü

**help :** Komut , parametre ve araç hakkındaki tüm bilgilere erişim için kullanılır.

**search :** exploit, payload, vb arama yapabiliriz. **search -h** parametresi ile yapılacak arama için uygun kriterler seçilir.

`      `**show :** istediğimiz bileşenleri listeleyebiliriz.

`     `**use** : listeden kullanmak istenilen exploit , payloadı vb seçilir.

**info :** Seçilen exploit gerekli ayarları , versiyon vb. gibi bilgileri gösterir.

**set :** Exploit , payload için gerekli düzenlemeler yapılır.

**unset :** Yapılan değişiklikler geri alınır.

**sessions :** Aktif olan oturumlar ve id bilgilerini listeler.

**Exploit :** Seçilen hedefe saldırı başlatır.

msf veritabanını baştlatmak için **service postgresql star**t komutunu ve veritabanını durdurmak için **service postgresql stop** komutu kullanılmaktadır. bu komutları uzun uzun yazmak yerine kendi aliaslarınızı oluşturarak daha kısa komutlar kullanabilirsiniz.

**alias posstart=’service postgresql start’**

**alias posstop=’service postgresql stop’**

`    `**OpenVAS**: Open Vulnerability Assessment System (Açık Güvenlik Açığı Değerlendirme Sistemi) anlamına gelen OpenVAS, güvenlik açığı yönetimi ve değerlendirmesi için kullanılan açık kaynaklı bir ağ güvenlik tarayıcısıdır. Kapsamlı taramalar yaparak sistem ve ağlardaki güvenlik açıklarını tespit etmek ve raporlamak için tasarlanmıştır.

OpenVAS'ın temel özellikleri şunları içerir:

1. **Güvenlik Açığı Taraması:** OpenVAS, bir ağ içindeki sunucular, ağ cihazları, uygulamalar ve diğer bileşenlerdeki güvenlik açıklarını belirlemek için taramalar gerçekleştirir. Saldırganların yararlanabileceği bilinen güvenlik sorunlarını, yanlış yapılandırmaları ve zayıflıkları kontrol eder.
1. **Güvenlik Açıkları Veritabanı:** Taranan sistemlerle karşılaştırmak için bilinen güvenlik açıklarından ve güvenlik kontrollerinden oluşan düzenli olarak güncellenen bir veritabanını kullanır. Bu veritabanı, CVE'ler (Ortak Güvenlik Açıkları ve Etkilenmeler) ve güvenlikle ilgili diğer veritabanları hakkında bilgiler içerir.
1. **Ölçeklenebilirlik ve Esneklik:** OpenVAS ölçeklenebilirdir ve küçükten büyüğe ağlara kadar çeşitli ortamlarda kullanılabilir. Farklı tarama yapılandırmalarını destekler ve kullanıcıların taramaları kendi özel gereksinimlerine göre özelleştirmelerine olanak tanır.
1. **Raporlama ve Düzeltme:** Belirlenen güvenlik açıklarını, bunların önem düzeylerini ve iyileştirme önerilerini vurgulayan ayrıntılı raporlar oluşturur. Bu raporlar, güvenlik sorunlarının etkili bir şekilde önceliklendirilmesine ve ele alınmasına yardımcı olur.
1. **Entegrasyon ve Otomasyon:** OpenVAS, diğer güvenlik araçları ve çerçeveleriyle entegrasyona olanak tanıyan API'ler ve komut satırı arayüzleri sağlar. Otomasyon yetenekleri, taramaların zamanlanmasına ve bunların daha büyük güvenlik süreçlerine entegre edilmesine olanak tanır.
1. **Açık Kaynak Topluluğu:** Açık kaynak olan OpenVAS, yazılımı sürekli olarak geliştiren ve güncelleyen, en son güvenlik tehditleri ve güvenlik açıklarıyla güncel kalmasını sağlayan katkıda bulunanlardan oluşan bir topluluktan yararlanır.

**Network scanners:**

**6. Ağ İzleme ve İstihbarat Araçları(IDS/IPS)** :Güvenlik analiz araçları, bir organizasyonun veya sistemlerin güvenliğini değerlendirmek, tehditleri tespit etmek, güvenlik açıklarını belirlemek ve uygun önlemleri almak için kullanılan çeşitli yazılım ve araçlardır. Bu araçlar, güvenlik olaylarını izlemek, analiz etmek ve yanıtlamak için çeşitli özelliklere ve yeteneklere sahiptir

`      `**Wireshark** :özgür ve açık kaynak kodlu bir ağ paket çözümleyicisidir. Bir ağ çözümleyicisi yakalanan ağ paket verilerini ayrıntılı bir şekilde sunar. Wireshark ağ sorunlarını giderme, ağ çözümleme, yazılım veya iletişim protokolü geliştirme ve eğitim amacıyla kullanılmaktadır. İlk olarak Ethereal adıyla başlayan proje, ticari marka sorunları nedeniyle Mayıs 2006'da Wireshark olarak yeniden adlandırılmıştır. Günümüzde en iyi paket çözümleyicilerinden biridir.

`      `Wireshark kullanım alanları:

-Ağ yöneticileri, ağ sorunlarını gidermek için kullanır.
-Ağ güvenliği mühendisleri, güvenlik sorunlarını incelemek için kullanır.
-QA mühendisleri bunu ağ uygulamalarını doğrulamak için kullanır.
-Geliştiriciler bunu protokol uygulamalarında hata ayıklamak için kullanır.
-İnsanlar bunu ağ protokolünün dahili özelliklerini öğrenmek için kullanır.
`       `Wireshark'ın sağladığı birçok özellikten bazıları:

-UNIX ve Windows işletim sistemleri için kullanılabilir.
-Bir ağ arayüzünden canlı paket verilerini yakalamak için kullanılabilir.
-Tcpdump / WinDump, Wireshark ve diğer birçok paket yakalama programıyla yakalanan paket verilerini içeren dosyalar açılabilir.
-Paket verisinin onaltılık dökümlerini içeren metin dosyalarından paketler Wireshark’a aktarılabilir.
-Paketler çok ayrıntılı protokol bilgileriyle görüntülenebilir.
-Yakalanan paket verileri kaydedilebilir.
-Paketlerin bir kısmını veya tamamını birkaç yakalama dosyası biçiminde dışa aktarılabilir.
-Paketler birçok kritere göre filtrelenebilir.
-Paketler birçok farklı kritere göre arama yapılabilir.
-Paket görüntüsünü filtrelere göre renklendirilebilir.
-Paketlerle ilgili çeşitli istatistikler oluşturulur.

`        `**NMAP**: Nmap (Network Mapper), açık kaynaklı ve popüler bir ağ tarama ve güvenlik hatası aracıdır. Sistem ve ağ desteği tarafından kullanılan Nmap, ağda bulunan cihazları ve ağdaki hedefi ayırmak, ağdaki açık portları tespit etmek, servisleri dayanıklılık ve ağ güvenliği açısından olası zayıf noktaları belirlemek için kullanılır.

Nmap'ın bazı temel özellikleri şunlardır:

1. **Ağ Tarama:** Hızlı ve kapsamlı bir şekilde ağda bulunan cihazların tespiti için kullanılabilir. TCP, UDP veya ICMP gibi farklı protokolleri kullanarak tarama yapabilir.
1. **Port Taraması:** Açık portları, çalışan servisleri ve bu servislerin parçalanıp birleştirilebileceğini tespit edebilir. Bu, güvenlik açısından önemli zayıf noktaların belirlenmesi için önemlidir.
1. **Servis Tanımlaması:** Hangi servislerin hangi portlarda çalıştığı ve bu servislere ait versiyonunun seçilebilmesidir. Bu sistem hangi yazılım sürümlerini çalıştırdığını kullanmak için kullanılır.
1. **Ağ Haritası Oluşturma:** Ağdaki cihazların ve bağlantıların haritasını, ağ görsel olarak sunabilir.
1. **Güvenlik Denetimi:** Ağ güvenliği açısından zayıf noktaları tespit etmek ve potansiyel saldırı vektörlerini belirlemek için kullanılabilir.

`     `**PRTG Network Monitor:** Ağda izlemek ve yönetmek için kullanılan bir araçtır. Cihazların, trafik verilerinin, bant genişliğinin ve diğer ağ unsurlarının belirtilerini gözlemlemek için kullanılır.

`    `**Zabbix:** Ağ izleme, performans ve sağlık durumu takibi için kullanılan açık kaynaklı bir araçtır. Sunucular, ağ cihazları ve uygulamalar gibi birçok bileşeni izleyebilir.

` `**SolarWinds Network Performance Monitor (NPM):** Ağ performansını izlemek, yönetmek ve analiz etmek için kullanılan bir ticari ağ izleme ve yönetim aracıdır. Ağdaki cihazların performansını ölçmek ve sorunları tespit etmek için kullanılır.

`  `**Tcpdump**: Unix ve Unix benzeri işletim sistemlerinde kullanılan, ağ trafiğini yakalamak ve analiz etmek için kullanılan bir komut satırı aracıdır. Temel olarak, ağ üzerindeki paketleri dinlemek, yakalamak ve bunları analiz etmek için kullanılır.

Tcpdump'un bazı temel özellikleri şunlardır:

1. **Ağ Trafik Yakalama:** Belirli bir ağ arayüzü üzerinden gelen ve giden ağ paketlerini dinler ve yakalar.
1. **Paket Filtreleme:** Belirli protokollere, portlara, IP adreslerine veya diğer özelliklere göre paketleri filtreleme ve yakalama yeteneği.
1. **Veri Yakalama:** Yakalanan paketleri bir dosyaya yazma ve bu dosyayı daha sonra analiz etmek için kullanabilme yeteneği.
1. **Esnek Kullanım:** Birçok seçenek ve filtreleme kriterleri kullanarak çeşitli durumları analiz etmek için kullanılabilir.

Tcpdump, genellikle ağ sorunlarını teşhis etmek, ağ trafiğini incelemek, güvenlik sorunlarını tespit etmek veya ağdaki iletişimi incelemek için kullanılır. Ayrıca, bu tür araçlar, ağ üzerindeki iletişimi anlamak, protokol davranışını incelemek ve ağ performansını analiz etmek için de kullanışlıdır

**Suricata:** Açık kaynaklı bir IDS/IPS sistemidir. Hızlı ve çok sayıda protokolü destekler ve ağ trafiğini izlerken saldırıları tespit etme ve önleme yetenekleri sunar.

**Zeek (eski adıyla Bro):** Ağ güvenliği için kullanılan açık kaynaklı bir platformdur. Ağ trafiğini analiz eder, detaylı günlükler oluşturur ve saldırıları tespit eder.

**7.Kimlik Doğrulama ve Erişim Kontrolü Araçları:** 
Kimlik doğrulama ve erişim kontrolü araçları, bir kullanıcının veya cihazın kimliğini doğrulamak ve ardından belirli kaynaklara erişim düzeyini denetlemek için kullanılan çeşitli yöntemleri ve araçları içerir. Bu araçlar, güvenlik seviyelerini artırmak, yetkilendirme süreçlerini yönetmek ve yetkisiz erişimi önlemek için kullanılır.

İşte bazı kimlik doğrulama ve erişim kontrolü araçlarının örnekleri:

1. `      `**Multi-Factor Authentication (MFA):** Kullanıcıların erişimini sağlamak için birden fazla kimlik doğrulama yöntemi kullanır. Örneğin, bir şifre veya PIN'in yanı sıra bir mobil cihazdan gelen onay kodu gibi ek güvenlik katmanları sunar. Örnekler arasında Google Authenticator, Microsoft Authenticator ve RSA SecurID bulunur.
1. **Single Sign-On (SSO):** Kullanıcıların farklı sistemlere tek bir kimlik doğrulama ile erişmesine izin verir. Bir kez oturum açtıklarında, SSO, kullanıcılara farklı uygulamalara veya sistemlere sorunsuz bir şekilde erişim sağlar. Okta, Azure Active Directory ve Ping Identity gibi çeşitli SSO çözümleri bulunmaktadır.
1. **Kimlik ve Erişim Yönetimi (IAM):** IAM, kullanıcıların kimliklerini ve erişim haklarını yöneten bir yönetim sürecidir. Bu tür araçlar, kullanıcı hesaplarını oluşturma, düzenleme, silme, rolleri belirleme ve erişim izinlerini yönetme gibi süreçleri içerir. Örnekler arasında Microsoft Azure Active Directory, Okta Identity Cloud, IBM Security Identity Governance and Intelligence (ISIGI) bulunur.
1. **Güvenlik Bilgi ve Olay Yönetimi (SIEM):** SIEM araçları, erişim izleme, olayları izleme, tehdit algılama ve yanıt verme gibi yetenekleri içerir. Bu araçlar, sistemlerdeki veya ağdaki kullanıcı erişim aktivitelerini izlemek ve anormal erişim davranışlarını tespit etmek için kullanılır.
1. **Biometrik Doğrulama:** Parmak izi, retina taraması, yüz tanıma gibi biyometrik özelliklerin kullanıldığı kimlik doğrulama yöntemleridir. Örnekler arasında biyometrik okuyucuların bulunduğu cihazlar veya uygulamalar yer alabilir.


**Kriptografi ve şifreleme araçlarının kullanımı ve önemi**
**
`  `Kriptografi ve şifreleme araçları, bilgiyi korumak ve gizliliği sağlamak için kullanılan önemli teknolojilerdir. Bunlar, verilerin yetkisiz erişimden korunması, gizliliğin sağlanması ve verilerin güvenli bir şekilde iletilmesi için kullanılır. Kriptografi, bilgiyi anlaması zor bir hale getirerek, güvenli bir şekilde iletilmesini ve saklanmasını sağlar.

İşte kriptografi ve şifreleme araçlarının kullanımı ve öneminin bazı ana noktaları:
### Veri Güvenliği Sağlar:
- **Gizlilik (Confidentiality):** Şifreleme, bilgilerin yetkisiz kişilerin erişiminden korunmasını sağlar. Şifrelenmiş veriler, şifrelenmeden önceki haline dönüştürülmedikçe anlaşılamaz.
- **Bütünlük (Integrity):** Kriptografik yöntemler, verilerin değiştirilmediğini veya bozulmadığını doğrular. Herhangi bir değişiklik tespit edildiğinde, bu durum belirlenebilir.
- **Kimlik Doğrulama (Authentication):** Kriptografik yöntemler, kullanıcıların veya sistemlerin kimliklerini doğrulamak için kullanılabilir. Örneğin, dijital imzalar kimlik doğrulama için kullanılabilir.
### İletişim Güvenliği Sağlar:
- **Güvenli İletişim (Secure Communication):** Şifreleme, iletişim sırasında verilerin korunmasını sağlar. Bu, hassas bilgilerin güvenli bir şekilde iletilmesini sağlar, özellikle internet üzerinden yapılan iletişimlerde.
### Çeşitli Şifreleme Yöntemleri ve Araçlar:
- **Simetrik ve Asimetrik Şifreleme:** Simetrik şifreleme, aynı anahtarın hem şifreleme hem de şifre çözme işlemlerinde kullanıldığı bir yöntemdir. Asimetrik şifreleme ise genellikle biri şifrelemek için kullanılan bir anahtar ve diğeri de şifreyi çözmek için kullanılan bir anahtar olmak üzere iki anahtar kullanır.
- **AES (Advanced Encryption Standard):** Simetrik şifreleme için popüler bir algoritmadır ve genellikle veri şifrelemek için kullanılır.
- **RSA ve ECC:** Asimetrik şifreleme algoritmalarıdır ve genellikle dijital imza ve güvenli iletişim için kullanılır.
### Önemli Kullanım Alanları:
- **Veri Güvenliği:** Hassas verilerin depolanması ve aktarılmasında kullanılır.
- **İnternet Güvenliği:** Güvenli iletişim, çevrimiçi işlemler ve kimlik doğrulama için kullanılır.
- **Endüstriyel Güvenlik:** Özellikle endüstriyel sistemlerde ve IoT (Nesnelerin İnterneti) cihazlarında kullanılarak, cihazların güvenliğini sağlar.


` `**OpenSSL**:  OpenSSL, bir açık kaynaklı sertifika yönetimini ve güvenlik protokollerini (özellikle SSL/TLS) destekleyen kriptografik fonksiyonları içeren bir kütüphanedir. Bu kütüphane, birçok farklı işletim sisteminde kullanılabilir ve genellikle ağ güvenliği ile ilgili çeşitli görevleri yerine getirmek için kullanılır. Örneğin, OpenSSL, bir web sunucusu veya bir istemci arasında güvenli bir iletişim kurulmasını sağlamak için kullanılabilir.

`   `OpenSSL, bir komut satırı arabirimi (CLI) ile kullanılır ve birçok farklı komut ve seçenekleri destekler. Örneğin, bir SSL/TLS sertifikası oluşturmak için aşağıdaki komut kullanılabilir:

||openssl req -new -newkey rsa:2048 -nodes -keyout example.key -out example.csr|
| :- | :- |


Bu komut, bir RSA anahtarı oluşturur ve bunu kullanarak bir sertifika İsteği (CSR) oluşturur. CSR, bir SSL/TLS sertifikası oluşturmak için bir sertifika otoritesine (CA) gönderilir ve daha sonra CA tarafından onaylandıktan sonra bir SSL/TLS sertifikası oluşturulur.

OpenSSL, ayrıca bir web sunucusu veya istemci tarafından SSL/TLS bağlantısı kurulmasını sağlamak için de kullanılabilir. Örneğin, aşağıdaki komut, bir web sunucusu tarafından bir SSL/TLS bağlantısı kurulmasını sağlar:

||openssl s\_server -accept 443 -key example.key -cert example.crt|
| :- | :- |

Bu komut, bir web sunucusu olarak çalışır ve 443 numaralı portuna gelen istekleri kabul eder. Özel anahtar ve sertifika dosyaları da belirtilir ve bu dosyalar, SSL/TLS bağlantısının kurulması için kullanılır.

OpenSSL, birçok farklı görevi yerine getirmek için kullanılabilir ve komut satırı arabirimine göre özelleştirilebilir.

**GnuPG (GNU Privacy Guard):** Açık kaynaklı bir şifreleme yazılımıdır. Dosyaları, iletişimi ve veritabanlarını şifrelemek ve dijital imzalar oluşturmak için kullanılır.

**VeraCrypt:** Açık kaynaklı bir disk şifreleme aracıdır. Sabit diskleri veya USB sürücüleri şifrelemek ve şifreli bir sanal disk oluşturmak için kullanılır.

**AES Crypt:** Açık kaynaklı ve kullanımı kolay bir dosya şifreleme aracıdır. Basit arayüzü sayesinde dosyaları hızlıca şifrelemek için kullanılır.

**Cryptomator:** Bulut depolama hizmetlerinde dosyaları şifrelemek için kullanılan açık kaynaklı bir araçtır.
















`                        `**Ağ Güvenliği Politikaları**

- Bilginin ve kaynakların paylaşılması gereksinimi sonucunda kurumlar, bilgisayarlarını çeşitli yollardan birbirine bağlayarak kendi bilgisayar ağlarını kurmuşlar ve sonra dış dünyayla iletişim kurabilmek için bilgisayar ağlarını İnternet’e uyarlamışlardır.
- Eskiden kilitli odalarla sağlanan güvenlik kavramı, bilgisayar ağları ve İnternet gibi ortamların gündeme gelmesiyle boyut değiştirmiştir. İnternet yasalarla denetlenemeyen bir sanal dünyadır. Bu sanal dünyada saldırganlar bilgiye ulaşmada ağların zayıf noktalarını kullanarak yasadışı yollar denemektedirler.
- Kurumların kendi kurmuş oldukları ve İnternet’e uyarladıkları ağlar ve bu ağlar üzerindeki kaynakların kullanılması ile ilgili kuralların genel hatlar içerisinde belirlenerek yazılı hale getirilmesi ile ağ güvenlik politikaları oluşturulur.
- Ağ güvenlik politikaları mümkünse sistem kurulmadan ve herhangi bir güvenlik sorunuyla karşılaşmadan önce oluşturulmalıdır.

Ağ güvenliğinin sağlanması için gerekli olan temel politikalar aşağıda sıralanmıştır: 

- 1. Kabul edilebilir kullanım (acceptable use) politikası 
- 2. Erişim politikası 
- 3. Ağ güvenlik duvarı (firewall) politikası 
- 4. İnternet politikası 
- 5. Şifre yönetimi politikası 
- 6. Fiziksel güvenlik politikası 
- 7. Sosyal mühendislik politikası

Kabul Edilebilir Kullanım (Acceptable Use) Politikası

- Ağ ve bilgisayar olanakların kullanımı konusunda kullanıcıların hakları ve sorumlulukları belirtilir. Kullanıcıların ağ ile nasıl etkileşimde oldukları çok önemlidir.
- Yazılacak politikada temelde aşağıdaki konular belirlenmelidir: 
  - Kaynakların kullanımına kimlerin izinli olduğu, 
  - Kaynakların uygun kullanımının nasıl olabileceği, 
  - Kimin erişim hakkını vermek ve kullanımı onaylamak için yetkili olduğu, 
  - Kimin yönetim önceliklerine sahip olabileceği, 
  - Kullanıcıların hakları ve sorumluluklarının neler olduğu, 
  - Sistem yöneticilerin kullanıcılar üzerindeki hakları ve sorumlulukların neler olduğu, 
  - Hassas bilgi ile neler yapılabileceği. 

`   `Erişim Politikaları

- Erişim politikaları kullanıcıların ağa bağlanma yetkilerini belirler. Her kullanıcının ağa bağlanma yetkisi farklı olmalıdır. Erişim politikaları kullanıcılar kategorilere ayrıldıktan sonra her kategori için ayrı ayrı belirlenmelidir. 

Bu kategorilere sistem yöneticileri de girmektedir. Sistem yöneticisi için erişim kuralları belirlenmediği takdirde sistemdeki bazı kurallar sistem yöneticisinin yetkisine bırakılmış olacağından, bu sistem üzerinde istenmeyen güvenlik açıkları anlamına gelebilecektir

`                  `Ağ Güvenlik Duvarı (Firewall) Politikası

- Ağ güvenlik duvarı (network firewall), kurumun ağı ile dış ağlar arasında bir geçit olarak görev yapan ve İnternet bağlantısında kurumun karşılaşabileceği sorunları çözmek üzere tasarlanan çözümlerdir. 
- Güvenlik duvarları salt dış saldırılara karşı sistemi korumakla kalmaz, performans arttırıcı ve izin politikası uygulayıcı amaçlar için de kullanılırlar.
- Güvenlik duvarı aşağıda belirtilen hizmetlerle birlikte çalışarak ağ güvenliğini sağlayabilmektedir: 
  - Proxy, 
  - Anti-Virus Çözümleri, 
  - İçerik Süzme (content filtering, 
  - Özel Sanal Ağlar (Virtual Private Network-VPN), 
  - Nüfuz Tespit Sistemleri (Intrusion Detection Systems-IDS).

`           `İnternet Politikası

- Kurum bazında her kullanıcının dış kaynaklara yani İnternet’e erişmesine gerek yoktur. İnternet erişiminin yol açabileceği sorunlar aşağıdaki gibidir: 
  - Zararlı kodlar,
  - Etkin Kodlar, 
  - Amaç dışı kullanım,
  - Zaman Kaybı.

`     `Şifre Yönetimi Politikası

- Şifreler kullanıcıların ulaşmak istedikleri bilgilere erişim izinlerinin olup olmadığını anlamamızı sağlayan bir denetim aracıdır. Şifrelerin yanlış ve kötü amaçlı kullanımları güvenlik sorunlarına yol açabileceğinden güvenlik politikalarında önemli bir yeri vardır.
- Sistem yöneticileri kullanıcıların şifre seçimlerinde gerektiği yerlerde müdahale etmelidirler. Basit ve kolay tahmin edilebilir şifreler seçmelerini engellemek için kullanıcılar bilinçlendirilmeli ve programlar kullanılarak zayıf şifreler saptanıp kullanıcılar uyarılmalıdır
- Ayrıca kurumlar güvenlik politikalarında şifre seçimi ile ilgili aşağıdaki kısıtlamları belirleyebilmektedirler: 
  - Şifrenin boyutu ve içeriği,
  - Süre dolması (eskime) politikası,
  - Tek kayıt ile her şeye erişim (Single Sign On-SSO) politikası.

Fiziksel Güvenlik Politikası

- Bilgisayar veya aktif cihazlara fiziksel olarak erişebilen saldırganın cihazın kontrolünü kolaylıkla alabileceği unutulmamalıdır. Ağ bağlantısına erişebilen saldırgan ise kabloya özel ekipmanla erişerek (tapping) hattı dinleyebilir veya hatta trafik gönderebilir. 

Açıkça bilinmelidir ki fiziksel güvenliği sağlanmayan cihaz üzerinde alınacak yazılımsal güvenlik önlemlerinin hiç bir kıymeti bulunmamaktadır.

Sosyal Mühendislik Politikası

- Sosyal mühendislik, kişileri inandırma yoluyla istediğini yaptırma ve kullanıcıya ilişkin bilgileri elde etme eylemidir. Sistem sorumlusu olduğunu söyleyerek kullanıcının şifresini öğrenmeye çalışmak veya teknisyen kılığında kurumun içerisine fiziksel olarak sızmak veya çöp tenekelerini karıştırarak bilgi toplamak gibi değişik yollarla yapılabilir. 
- Kurum çalışanları kimliğini kanıtlamayan kişilere kesinlikle bilgi aktarmamalı, iş hayatı ile özel hayatını birbirinden ayırmalıdır. Kurum politikasında bu tür durumlarla ilgili gerekli uyarılar yapılmalı ve önlemler alınmalıdır.

**Ağ güvenliği politikalarının oluşturulması**

Kurumun İhtiyaçlarının Belirlenmesi

- Güvenlik Politikalarının oluşturulması sırasındaki ilk adım olarak bu politikanın kurumun hangi gereksinimlerine yönelik oluşturulacağı belirlenmelidir. Politikanın oluşması için aşağıdaki aşamalar yerine getirilmelidir: 
  - Korunacak nesnelerin belirlenmesi,
  - Kime karşı korumanın yapılacağının belirlenmesi,
  - Bilgileri saklama yönteminin belirlenmesi,
  - Bilgilerin arşivlenmesi ve yedeklenmesi,
  - Kurum içerisinde sorumlulukların belirlenmesi,
  - Yaptırım gücünün belirlenmesi.

Risk Analizi Ve Güvenlik Matrislerinin Oluşturulması

- Risk analiziyle kurumun ağına, ağ kaynaklarına ve verilere yapılabilecek saldırılarla oluşabilecek riskler tanımlanır. Amaç değişik ağ bölümlerindeki tehdit tahminlerinin belirlenmesi ve buna uygun bir düzeyde güvenlik önlemlerinin uygulanmasıdır. 
- Oluşabilecek tehdidin önemine ve büyüklüğüne göre üç düzey kullanılabilir; Düşük Risk, Orta Risk, Yüksek Risk.
- Riskler tanımlandıktan sonra sistemin kullanıcıları tanımlanmalıdır. Kullanıcı türleri aşağıdaki gibi sınıflandırılabilir: 
  - Yöneticiler: Ağ kaynaklarını yönetme sorumluluğundaki iç kullanıcılar.
  - Öncelikliler (priviliged): Kullanıcılardan daha fazla erişim hakkına gereksinim duyan iç kullanıcılar. 
  - Kullanıcılar: Genel erişim hakkına sahip iç kullanıcılar. 
  - İş Ortakları: Bazı kaynaklara erişim gereksinimi duyacak dış kullanıcılar. 
  - Diğer: Dış kullanıcılar veya müşteriler.

`       `**Güvenlik Politikasının Uygulanması**

- Kurumun gereksinimlerinin belirlenmesi ve risk analizi sonucunda güvenlik politikası bir sorumlu veya bir kurul tarafından oluşturulmaktadır. Güvenlik politikası uygulanmadan önce aşağıdaki koşullar sağlanmalıdır: 
  - Politika hazırlanırken katılım sağlanmalıdır,
  - Politika standartlara uyumlu olmalıdır: IETF’in “Security Policy Specification Language“ (SPSL), Sun Systems’in “Generic Security Services API“ (GSSAPI) ve “Pluggable Authentication Modules“ (PAM) verilebilir.
  - Yönetimin onayı alınmalı ve politika duyurulmalıdır,
  - Acil durum politikası oluşturulmalıdır.


- Politikalar oluşturulduktan ve duyurulduktan sonra uygulanmalıdır. Politikada belirtilen kuralların uygulanması için korunacak sistemler üzerinde veya ağ cihazlarında gerekli teknik ayarlar yapılmalıdır. Örneğin güvenlik matrisinde oluşturulan erişim kuralları ve hangi sunuculara hangi protokoller üzerinden erişilebileceği güvenlik duvarı veya erişim listeleri (access-list) yöntemleri kullanılarak oluşturulmalıdır. 
- Fakat daha önemlisi ayarlanan güvenlik sistemleri sık sık sınanmalı, risk haritası çıkarılmalı, sistemin zayıf noktaları saptanıp gerekli önlemler alınmalıdır. Logların incelenmesi ile güvenlik politikasının amacına ulaşıp ulaşmadığı anlaşılabilir.

` `**Sonuç**

- Bilgisayar ağlarında güvenlik politikasının uygulanması kritik önem taşımaktadır. Kurumsal güvenlik için öncelikle yazılı olarak kurallar belirlenmelidir. 
- Bir güvenlik politikası yaratmanın en önemli adımı planlamadır. 
- Güvenlik politikası oluşturulurken kurumun en alt düzeylerine kadar inerek gereksinimler belirlenmelidir. 
- Aynı zamanda oluşturulan politikalar dikkatli bir şekilde uygulanmalıdır. Güvenlik politikasının etkin olması için üst yönetimin desteği sağlanmalı ve kurumun çalışanları kullanılan politika konusunda bilgilendirilmelidir.
- Güvenlik politikasının etkin olması için üst yönetimin desteği sağlanmalı ve kurumun çalışanları kullanılan politika konusunda bilgilendirilmelidir.
- Güvenlik politikaları bir kez hazırlanıp sonra değişmeyen kurallar değildir. 
- Güvenlik politikası değişen tehditlere, zayıflıklara ve kurum politikalarına göre yeniden değerlendirilmeli ve gerekli değişiklikler yapılmalıdır


`                                            `**HAZIRLAYAN :SELÇUK BİLGİN - 402527**



# Security Guard – dokumentacja

[English](README.md) | **Polski**

Dokumentacja dla wersji wtyczki **1.03** (ResourceSpace 11).
Znacznik *(od X.YY)* oznacza wersję wtyczki, od której funkcja jest dostępna. Funkcje bez
znacznika są dostępne od wersji 1.00. Historia zmian: [CHANGELOG.md](CHANGELOG.md).

Wtyczka chroni ResourceSpace przed znanymi słabościami, zanim zostaną poprawione w samym
ResourceSpace (**wirtualne łatki**), i działa jako **lekki firewall aplikacyjny**: listy
dozwolonych i blokowanych adresów IP, blokowanie skanerów, limity logowania przez API
i SimpleSAMLphp, wzorce ataków w parametrach oraz log bezpieczeństwa, z którego fail2ban może
blokować adresy w firewallu systemu. Chroni też przed **usunięciem wielu zasobów naraz**
(zatwierdzenie przez drugiego administratora) i egzekwuje **politykę udostępniania** (hasło,
generowane hasła, okres ważności) *(od 1.01)*, a o **incydentach bezpieczeństwa** powiadamia
wskazanych użytkowników i grupy użytkowników *(od 1.02)*.

**Gdzie:** System > Plugins > Security Guard > **Options**. Stronę otwierają tylko administratorzy
(uprawnienie `a`).

**Czego wtyczka nie zrobi:** widzi tylko żądania, które docierają do kodu PHP ResourceSpace. Pliki
statyczne, sam serwer WWW i sieć są poza jej zasięgiem – na stronie opcji są szablony nginx
i fail2ban do tych części (Apache: zob. „Apache zamiast nginx”). Wirtualne łatki nie zastępują aktualizacji: aktualizuj ResourceSpace
i zgłaszaj słabości zespołowi ResourceSpace.

---

## Jak działa i obciążenie

Kontrole działają w hooku `initialise` na końcu `include/boot.php` – na każdej stronie, w API
i na stronach SimpleSAMLphp (gdy SimpleSAMLphp ładuje ResourceSpace, zob. niżej), **przed** kodem
strony i przed uwierzytelnieniem. Wtyczka jest zawsze ładowana dla wszystkich użytkowników
(`disable_group_select`) i działa jako pierwsza (`default_priority: 1`).

Prawie nie obciąża serwera:

- zwykłe żądanie: kilka porównań tekstów i jedno wczytanie pliku ustawień (tablica PHP trzymana
  w pamięci przez OPcache) – bez zapytań do bazy, bez zapisu na dysk,
- baza tylko przy logowaniu przez API (jedno zapytanie) i przy żądaniach usuwających zasoby (dwa–trzy
  małe zapytania) *(od 1.01)*, dysk tylko przy zablokowanym lub zalogowanym żądaniu i przy wysłaniu
  formularza logowania SimpleSAMLphp (mały plik licznika),
- nie wymaga APCu ani innych rozszerzeń.

## Łatki na znane słabości

Każdą łatkę można wyłączyć osobno.

| Opcja | Słabość | Co robi wtyczka |
|---|---|---|
| Report dates only as numbers | SQL injection w parametrach dat raportów (`pages/team/team_report.php`, także wykresy analityki i raporty e-mailem) | `from-y`, `from-m`, `from-d`, `to-y`, `to-m`, `to-d` (i `period_days`) mogą zawierać tylko cyfry, inaczej żądanie jest blokowane (400). |
| Redirect after login only to this site | Open redirect: `login.php?url=//inna-strona` po zalogowaniu przenosił na obcą stronę | Parametr `url` w `login.php` i `pages/terms.php` musi być ścieżką w tym serwisie albo zaczynać się od `$baseurl`; inaczej jest zamieniany na `index.php` i logowany. |
| API: one source of the function name | `api/index.php` decydował o uwierzytelnieniu na podstawie innej kopii `function` niż wykonywana – `function=login` poza `query` pomijał uwierzytelnienie | Parametr `function` poza `query` musi być taki sam jak funkcja w `query`, inaczej 403. Interfejs w przeglądarce (`authmode=native`) takiego parametru nie wysyła. |
| API login lockout | Brute force przez API: `function=login` nie był ograniczany, blokady sprawdzał tylko `login.php` | Logowanie przez API jest odrzucane (429), dopóki ResourceSpace blokuje adres IP lub nazwę użytkownika (`$max_login_attempts_per_ip`, `$max_login_attempts_per_username`, `$max_login_attempts_wait_minutes`) – tak samo jak w `login.php`. |
| Session only from the cookie | Hash sesji był przyjmowany w adresie (`?user=…`) i mógł trafić do logów i historii przeglądarki | `user` jest usuwany z parametrów adresu poza API (tam `user` to nazwa użytkownika). ResourceSpace 10.7 nigdy nie tworzy takich linków. |
| One session per account (domyślnie wyłączona) | Session fixation: bez `$randomised_session_hash` hash sesji zależy tylko od hasła i dnia | Ustawia `$randomised_session_hash = true`: nowa losowa sesja przy każdym logowaniu. **Zalogowanie na drugim urządzeniu kończy sesję na pierwszym.** |

## SimpleSAMLphp

Gdy SimpleSAMLphp czyta konfigurację z ResourceSpace (`$simplesaml_rsconfig`, ustawienia
w `$simplesamlconfig` w `config.php`), jego autoloader ładuje ResourceSpace, więc wtyczka działa też
na stronach SimpleSAMLphp. Wtedy:

- **Hide error details** – ustawia `showerrors` i `errorreporting` na `false`: strony błędów bez
  śladu stosu i ścieżek serwera.
- **Lokalny formularz logowania i strony admina** (`module.php/core/loginuserpass`, `core/login`,
  `core/frontpage`, `admin`): *open*, *allowlist* (tylko adresy z „Admin pages only from”) albo
  *blocked*. Samo SSO (`module.php/saml/...`) nigdy nie jest blokowane.
- **Próby logowania na IP** – najwyżej N wysłań lokalnego formularza z jednego adresu w M minut
  (domyślnie 10 w 10 minut), potem 429.

**Sprawdź po aktywacji** (zależy od wersji SimpleSAMLphp w ResourceSpace 11): otwórz lokalną
stronę logowania z adresu spoza listy – powinna odpowiedzieć „Request blocked”. Jeśli nie,
SimpleSAMLphp na tym serwerze nie ładuje ResourceSpace: użyj szablonu nginx ze strony opcji (Apache: „Apache zamiast nginx”).

## Firewall

Listy przyjmują jeden adres (`192.0.2.10`, `2001:db8::1`) lub sieć (`192.0.2.0/24`) w wierszu;
tekst po `#` to komentarz. Pusta lista wyłącza regułę.

- **Trusted proxies** – adresy load balancera / reverse proxy. Tylko dla żądań od nich adres
  klienta jest brany z `X-Forwarded-For` (ostatni adres, który nie jest zaufanym proxy). Bez tej
  listy wtyczka używa `REMOTE_ADDR`.
- **Blocked addresses** – brak dostępu do ResourceSpace.
- **Admin pages only from** + **Admin pages** – strony administracyjne (domyślnie `pages/admin/`,
  `pages/team/`, `plugins/*/pages/`) tylko z tych adresów. Strona opcji nie zapisze listy bez
  Twojego adresu.
- **API key access only from** – wywołania z kluczem API tylko z tych adresów. Interfejs
  w przeglądarce (`authmode=native`) działa bez zmian.
- **Block scanners** – User-Agent zawiera np. `sqlmap`, `nikto`, `nuclei`, `wpscan` (lista do
  edycji). Zatrzymuje automatyczny szum, nie ostrożnego atakującego.
- **Attack patterns in parameters** – *off*, *log only* (domyślnie) lub *block*: typowe SQL
  injection (`union select`, `sleep(`, `information_schema`, `' or 1=1`), XSS (`<script`,
  `javascript:`, `onerror=`) i path traversal (`../../`, `/etc/passwd`). Ścieżki z listy pod spodem
  nie są sprawdzane (edytory wysyłające kod, np. Custom CSS). Zacznij od *log only*, sprawdź log
  pod kątem fałszywych alarmów, potem przełącz na *block*.

Zablokowane żądanie dostaje tylko krótką odpowiedź z numerem referencyjnym; powód jest w logu
(reguła, adres, ścieżka, numer).

## Nagłówki odpowiedzi

- **Remove X-Powered-By** – ukrywa wersję PHP.
- **Permissions-Policy** – domyślnie `camera=(), microphone=(), geolocation=(), payment=(), usb=()`;
  puste = nagłówek nie jest wysyłany.

Pozostałe nagłówki (HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy) i
baner serwera należą do serwera WWW (nginx: `server_tokens off`; Apache: `ServerTokens Prod`,
`ServerSignature Off` – zob. „Apache zamiast nginx”).

## Ochrona przed usuwaniem *(od 1.01)*

Chroni przed utratą wielu zasobów naraz – przez pomyłkę, przez skrypt działający w sesji
użytkownika albo z przejętego konta. ResourceSpace nie ma hooka, który pozwoliłby zatrzymać trwałe
usunięcie przed skasowaniem plików, więc wtyczka sprawdza żądania usuwające, zanim wykona się kod
strony:

- funkcje API `delete_resource`, `delete_resources_in_collection` i `delete_alternative_file`
  (tak usuwa interfejs: „Delete” na stronie zasobu, „Delete all resources” w akcjach kolekcji),
- `pages/collection_manage.php` – usunięcie kolekcji razem z zasobami,
- edycja zbiorcza kolekcji ustawiająca stan „Deleted”.

Opcje:

- **Always move to "Deleted" first** – gdy `$resource_deletion_state` nie jest ustawione, usunięcie
  od razu kasuje pliki; wtyczka ustawia 3 („Deleted”), więc usunięte zasoby można przywrócić.
  Trwale usuwa dopiero ponowne usunięcie zasobu, który już jest w „Deleted”.
- **Limity na użytkownika i okres** (domyślnie 50 zasobów przeniesionych do „Deleted” i 10
  usuniętych trwale w 60 minut; 0 trwałych = każde trwałe usunięcie wymaga zatwierdzenia). Wtyczka
  liczy usunięcia użytkownika z logu ResourceSpace (`resource_log`) plus zasoby z bieżącego
  żądania.
- **Permanent deletion in the browser**: *w ramach limitu* albo *zablokowane* (wtedy zasoby
  z „Deleted” może trwale usunąć tylko administrator na serwerze, np.
  `pages/tools/purge_deleted_resources.php`).

**Dodatkowa autoryzacja – zatwierdzenie („cztery oczy”):** po przekroczeniu limitu usunięcie jest
zatrzymane, użytkownik widzi „needs the approval of another administrator (request #N)”,
a administratorzy dostają powiadomienie w ResourceSpace. W ramce **Deletion approvals**
administrator zatwierdza wniosek na określony czas (domyślnie 60 minut); użytkownik powtarza
usunięcie, a zgoda zużywa się zasób po zasobie. Przy **Four eyes** (domyślnie) nikt nie zatwierdzi
własnego wniosku. Administrator może też **zatwierdzić z góry** (nazwa użytkownika, liczba zasobów,
minuty) przed planowanym porządkowaniem i wycofać aktywną zgodę.

Dlaczego zatwierdzenie przez drugą osobę: ponowne wpisanie hasła nie działa dla użytkowników SSO
(nie mają hasła w ResourceSpace) i nie pomaga przy przejętej sesji; kody e-mail wymagają działającej
poczty i trafiają do tej samej osoby. Drugi administrator nie zależy od sposobu logowania.

Poza zakresem: skrypty uruchamiane na serwerze (wiersz poleceń) i pliki usuwane bezpośrednio na
dysku – na to kopie zapasowe i snapshoty filestore oraz bazy.

## Polityka udostępniania *(od 1.01)*

Zasady dla udostępnień zewnętrznych (linki z kluczem dostępu) – w formularzach udostępniania
i wysyłki e-mailem zasobów i kolekcji oraz przy udostępnianiu uploadu. Domyślnie wyłączona;
włącz „Share policy is on”.

- **Password required** – ustawia `$share_password_required`, które ResourceSpace sprawdza na serwerze.
- **Propose a generated password** – pole hasła jest wypełniane losowym hasłem o minimalnej długości
  (litery, cyfry, symbole, bez mylących znaków jak 0/O, 1/l) i jest widoczne, więc można je
  skopiować dla odbiorcy; „New password” generuje kolejne. Użytkownik może wpisać własne hasło.
- **Minimalna długość hasła** (domyślnie 12) – krótsze hasła są odrzucane na serwerze.
- **Okres ważności** – domyślna liczba dni (14) i maksimum (30). Lista dat ważności pokazuje tylko
  daty do maksimum; na serwerze data jest poprawiana do limitów (udostępnienie z inną datą dostaje
  najbliższą dozwoloną, w logu `share_expiry`).
- **Users may change the expiry date** – wyłączone = każde udostępnienie wygasa po domyślnej
  liczbie dni (lista pokazuje tylko tę datę).
- **Allow "Never"** – udostępnienia bez daty ważności (tylko gdy użytkownik może zmieniać datę).

Istniejące udostępnienia się nie zmieniają; polityka działa przy tworzeniu i edycji udostępnienia.

## Powiadomienia o incydentach *(od 1.02)*

Incydenty bezpieczeństwa trafiają do wskazanych **użytkowników** (nazwy użytkowników) i do wszystkich
aktywnych członków wskazanych **grup użytkowników**:

- **powiadomienie ResourceSpace** (dzwonek / wiadomości) z linkiem do strony opcji,
- **e-mail** na adres z konta użytkownika (konta z adresem oznaczonym jako nieprawidłowy są
  pomijane; ResourceSpace musi mieć skonfigurowaną wysyłkę poczty).

Rodzaje incydentów (każdy włączany osobno):

| Rodzaj | Zdarzenia |
|---|---|
| Zablokowane ataki | blokowane adresy, skanery, strony admina / klucze API z innych adresów, pomylenie „function” w API, parametry raportów, wzorce ataków w trybie „block”, panel SimpleSAMLphp |
| Ataki na logowanie | blokada logowania przez API, limit logowania SimpleSAMLphp |
| Usuwanie wielu zasobów | wnioski o zatwierdzenie (także do administratorów, gdy włączone „Notify administrators”), zablokowane trwałe usuwanie, udzielone zgody |
| Wykrycia bez blokady | wzorce ataków w trybie „log only”, poprawione przekierowanie po logowaniu, hash sesji w adresie |
| Zmiany Security Guard | zapis ustawień (ze zmienionymi opcjami), wyłączenie ochrony, usunięcie logu, reset wtyczki, powiadomienie testowe |

Przeciw zalewowi: jedno powiadomienie na regułę i adres w ciągu N minut (domyślnie 15) i najwyżej
M powiadomień na godzinę (domyślnie 30); log bezpieczeństwa zapisuje każde zdarzenie. Powiadomienia
są wysyłane tylko, gdy coś się dzieje – zwykłe żądania nadal nie odpytują bazy.

„Send test notification” wysyła próbę do zapisanych odbiorców zapisanymi kanałami. Użytkownicy,
którzy w preferencjach ResourceSpace mają wysyłanie każdego powiadomienia także e-mailem, mogą
dostać dwa e-maile – wtedy zostaw włączony jeden kanał.

## Log bezpieczeństwa i fail2ban

Każde zdarzenie to jeden wiersz w `<filestore>/security_guard/data_<klucz>/events.log`, np.:

```
2026-11-13T10:00:00+01:00 [security_guard] action=block rule=api_confusion ip=192.0.2.7 ref=3f9a1c2b7d method=POST path="/api/index.php" detail="..."
```

`action=block` – żądanie zatrzymane, `action=fix` – poprawiony parametr (przekierowanie, sesja
w adresie), `action=log` – tylko zapis (wzorce ataków w trybie *log only*). Strona opcji pokazuje
200 najnowszych zdarzeń i pozwala usunąć log; po przekroczeniu ustawionego rozmiaru plik dostaje
nazwę `events.log.1`.

Na stronie opcji jest gotowy filtr i jail **fail2ban** z prawdziwą ścieżką logu: adres
zablokowany 5 razy w 10 minut trafia na godzinę do firewalla systemu. Za proxy lub load
balancerem serwer widzi tylko adres proxy – blokuj wtedy na proxy.

## Kontrola konfiguracji

Lista ustawień ResourceSpace i PHP ważnych dla bezpieczeństwa (OK / WARN / INFO): losowy hash
sesji, `$ip_forwarded_for` (klient może podrobić `X-Forwarded-For` i obejść blokadę logowania na
IP), HTTPS, debug log, długość hasła, blokady logowania, bezczynne sesje, zdalne API,
`display_errors`, `expose_php`, APCu, wersja TinyMCE dołączona do ResourceSpace, SimpleSAMLphp
i wyłącznik awaryjny.

## Wyłączenie z poziomu serwera (awaryjnie)

Jeśli wtyczka blokuje coś, czego nie powinna – np. po aktualizacji ResourceSpace – a strona opcji
jest niedostępna, użyj jednego ze sposobów (od najszybszego; strona opcji pokazuje je
z prawdziwymi ścieżkami serwera):

```bash
# 1. wyłączenie wszystkich kontroli; wtyczka zostaje aktywna (usunięcie pliku włącza je znowu)
sudo -u www-data mkdir -p <filestore>/security_guard
sudo -u www-data touch <filestore>/security_guard/disabled
sudo rm <filestore>/security_guard/disabled               # ponowne włączenie

# 2. albo wiersz w <RS_ROOT>/include/config.php
$security_guard_disable = true;

# 3. usunięcie kodu - ResourceSpace pomija wtyczkę bez plików, ustawienia zostają w filestore
sudo mv <RS_ROOT>/plugins/security_guard /root/security_guard.off
sudo mv /root/security_guard.off <RS_ROOT>/plugins/security_guard   # przywrócenie

# 4. dezaktywacja w bazie (jak System > Plugins > Deactivate)
mysql <baza> -e "UPDATE plugins SET inst_version = NULL WHERE name = 'security_guard';"
sudo rm -f <filestore>/tmp/querycache/plugins_*   # cache listy wtyczek ($tempdir/querycache, jeśli ustawiony)
```

- 1 i 2 działają od razu i zachowują ustawienia. 2 działa także, gdy filestore nie jest
  zapisywalny.
- 3 pomaga nawet wtedy, gdy błąd powoduje sam kod wtyczki (np. nowsza wersja PHP).
- Po aktualizacji ResourceSpace: otwórz stronę opcji, sprawdź w logu nieoczekiwane wiersze
  `block` i przetestuj logowanie, SSO, API i raporty. Błąd wewnątrz wtyczki nigdy nie zatrzymuje
  strony – jest przechwytywany i zapisywany tylko w debug logu.

## Apache zamiast nginx

Kontrole wtyczki nie zależą od serwera WWW. Reguły serwera ze strony opcji (napisane dla nginx)
w Apache wyglądają tak – moduły `headers` i `remoteip` (`sudo a2enmod headers remoteip` w Ubuntu / Debian,
w rodzinie RHEL ładowane domyślnie):

```apache
# Baner serwera - /etc/apache2/conf-available/security.conf (RHEL: /etc/httpd/conf.d/security.conf)
ServerTokens Prod
ServerSignature Off

# VirtualHost ResourceSpace
<Directory <RS_ROOT>>
    Options -Indexes +FollowSymLinks
</Directory>

# SimpleSAMLphp: lokalny formularz logowania i strony admina tylko z tych adresów (SSO bez zmian)
<LocationMatch "^/plugins/simplesaml/lib/(public|www)/(admin|module\.php/(admin|core/(login|loginuserpass|frontpage)))">
    Require ip 192.0.2.10
</LocationMatch>

# brak dostępu do ukrytych plików i kopii zapasowych
<LocationMatch "/\.(?!well-known)">
    Require all denied
</LocationMatch>
<FilesMatch "\.(bak|old|orig|sql|swp|log)$">
    Require all denied
</FilesMatch>

# za load balancerem / reverse proxy: prawdziwy adres klienta w REMOTE_ADDR
RemoteIPHeader X-Forwarded-For
RemoteIPTrustedProxy 192.0.2.1
```

- Z `mod_remoteip` Apache sam przekazuje prawdziwy adres klienta – pole „Trusted proxies” we wtyczce
  zostaw puste. Bez niego wpisz tam adresy proxy.
- Apache nie ma wbudowanego odpowiednika `limit_req` z nginx. Limity wtyczki (blokada logowania przez
  API, limit logowania SimpleSAMLphp) działają niezależnie; dodatkowo użyj fail2ban (jail ze strony
  opcji czyta log wtyczki, więc jest taki sam dla Apache) i ewentualnie `mod_evasive` albo ModSecurity.
- Nagłówek `X-Powered-By` usuwa wtyczka; HSTS i pozostałe nagłówki można ustawić przez
  `Header always set ...` (mod_headers).
- Wyłącznik awaryjny przy Apache w rodzinie RHEL: `sudo -u apache touch <filestore>/security_guard/disabled`.
- Sprawdzenie i przeładowanie: `sudo apachectl configtest`, potem `sudo systemctl reload apache2` (RHEL: `httpd`).

## Instalacja i pliki na serwerze

### Pobranie i instalacja

Wtyczka jest dystrybuowana jako archiwum `security_guard-<wersja>.zip` na stronie wydań:
<https://github.com/s29829/security_guard/releases>. Archiwum zawiera katalog `security_guard/` z kodem, licencją
i dokumentacją. Poniżej `<RS_ROOT>` to katalog instalacji ResourceSpace (np.
`/var/www/resourcespace`), a `www-data:www-data` to użytkownik i grupa, które uruchamiają PHP – przy Apache w RHEL, Rocky, Alma
czy Fedorze `apache:apache` (zob. „nginx czy Apache” niżej).

**Przez przeglądarkę:** Plugin Manager > Upload a plugin > wybierz plik `.zip` > Upload (przy
aktualizacji: **Overwrite**).

**Z wiersza poleceń (CLI)** – pobranie, rozpakowanie i uprawnienia:

```bash
VER=<wersja>                     # numer wersji ze strony wydań, np. 1.00
cd /tmp
curl -fLO https://github.com/s29829/security_guard/releases/download/v$VER/security_guard-$VER.zip
sudo rm -rf <RS_ROOT>/plugins/security_guard        # tylko przy aktualizacji (dane wtyczki są w filestore)
sudo unzip -q security_guard-$VER.zip -d <RS_ROOT>/plugins/
sudo chown -R www-data:www-data <RS_ROOT>/plugins/security_guard
sudo find <RS_ROOT>/plugins/security_guard -type d -exec chmod 755 {} \;
sudo find <RS_ROOT>/plugins/security_guard -type f -exec chmod 644 {} \;
```

**Przez git:** repozytorium <https://github.com/s29829/security_guard> zawiera pełny katalog wtyczki:

```bash
sudo git clone https://github.com/s29829/security_guard <RS_ROOT>/plugins/security_guard
sudo chown -R www-data:www-data <RS_ROOT>/plugins/security_guard
```

Aktualizacja: `sudo git -C <RS_ROOT>/plugins/security_guard pull`.

### nginx czy Apache

Wtyczka działa tak samo z oboma serwerami WWW. Różnią się tylko użytkownik uruchamiający PHP, nazwy
usług i kilka ustawień serwera – w poleceniach wyżej użyj użytkownika i grupy z tabeli:

| | nginx + PHP-FPM (Ubuntu / Debian) | Apache (Ubuntu / Debian) | Apache (RHEL, Rocky, Alma, Fedora) |
|---|---|---|---|
| Użytkownik:grupa uruchamiające PHP | `www-data:www-data` | `www-data:www-data` | `apache:apache` |
| Przeładowanie po aktualizacji | `sudo systemctl restart php8.3-fpm` | mod_php: `sudo systemctl reload apache2`; PHP-FPM: `sudo systemctl restart php8.3-fpm` | mod_php: `sudo systemctl reload httpd`; PHP-FPM: `sudo systemctl restart php-fpm` |

- **Kto uruchamia PHP:** przy Apache z mod_php – użytkownik Apache; przy PHP-FPM (nginx lub Apache) –
  użytkownik puli PHP-FPM (`user =` / `group =` w `/etc/php/<wersja>/fpm/pool.d/www.conf`, w rodzinie RHEL
  `/etc/php-fpm.d/www.conf`). Sprawdzenie: `ps -o user= -C php-fpm8.3,php-fpm,apache2,httpd | sort -u`.
- **Uprawnienia:** katalogi `755`, pliki `644`, właściciel = ten użytkownik i grupa (polecenia wyżej).
  Pliki wtyczki muszą być tylko czytelne; `<filestore>` musi być zapisywalny dla tego użytkownika – tak
  samo, jak wymaga tego ResourceSpace.
- **Bez listowania katalogów (Apache):** Apache w Ubuntu / Debian pozwala listować katalogi w `/var/www`
  (`Options Indexes` w `apache2.conf`). Wtyczka trzyma ustawienia w `<filestore>/<wtyczka>/data_<klucz>/`,
  a listing pokazałby nazwę tego katalogu. Wyłącz listowanie dla ResourceSpace (VirtualHost albo
  `apache2.conf` / `httpd.conf`) i przeładuj Apache:

  ```apache
  <Directory <RS_ROOT>>
      Options -Indexes +FollowSymLinks
  </Directory>
  ```

  nginx nie listuje katalogów, jeśli nie ustawiono `autoindex on`.
- **SELinux (rodzina RHEL):** po rozpakowaniu przywróć etykiety plików:
  `sudo restorecon -R <RS_ROOT>/plugins/security_guard`. Filestore potrzebuje etykiety do zapisu (zwykle ustawionej
  przy instalacji ResourceSpace): `sudo semanage fcontext -a -t httpd_sys_rw_content_t "<filestore>(/.*)?"`
  i `sudo restorecon -R <filestore>`.
- **Reguły serwera** (limity zapytań, ukryte pliki, panel SimpleSAMLphp, baner serwera): strona opcji
  pokazuje szablony nginx; odpowiedniki dla Apache są w „Apache zamiast nginx” niżej.

Na koniec: System > Plugins, aktywuj „Security Guard” i kliknij **Options**. W ustawieniach
domyślnych włączone są wszystkie łatki poza „One session per account”, listy firewalla są puste,
a wzorce ataków są tylko logowane – w pierwszych dniach przeglądaj log. Ochrona przed usuwaniem
jest włączona z limitami opisanymi wyżej; polityka udostępniania jest wyłączona, dopóki jej nie
włączysz *(od 1.01)*.

### Pliki na serwerze

Wszystko, co zapisuje wtyczka, jest w `<filestore>/security_guard/`:

- `data_<klucz>/settings.php` – ustawienia (klucz pochodzi od `scramble_key`, więc plików nie da się
  odczytać, zgadując adres),
- `data_<klucz>/events.log`, `events.log.1` – log bezpieczeństwa,
- `data_<klucz>/rate/` – liczniki prób logowania i powiadomień (stare są usuwane automatycznie),
- `data_<klucz>/deletion.json` – wnioski o zatwierdzenie usunięcia i zgody *(od 1.01)*,
- `disabled` – wyłącznik awaryjny, tylko gdy go utworzysz.

`<filestore>` to `$storagedir` ResourceSpace (domyślnie `<RS_ROOT>/filestore`). Aktualizacja ani
usunięcie kodu wtyczki nie kasuje tych plików. **Wtyczka sama tworzy swoje katalogi** przy
pierwszym zapisie; potrzebuje tylko prawa zapisu do filestore, które ResourceSpace i tak wymaga.

## Reset wtyczki

Ramka jest zwinięta – kliknij tytuł, aby ją rozwinąć; otwiera się sama po nieudanym resecie.

**Reset plugin** (po wpisaniu `RESET`) usuwa `<filestore>/security_guard`: ustawienia, log, liczniki,
wnioski i zgody na usunięcie oraz plik wyłącznika awaryjnego. Potem obowiązują ustawienia domyślne. Dane ResourceSpace się nie
zmieniają. Operacji nie można cofnąć.

## Licencja

- Wtyczka jest udostępniona na licencji **PolyForm Noncommercial License 1.0.0** (plik
  [LICENSE](LICENSE)).
- **Bezpłatnie** można jej używać prywatnie i w celach niekomercyjnych, a także w organizacjach
  niekomercyjnych (edukacja, instytucje publiczne, organizacje charytatywne). Można ją zmieniać
  i udostępniać w tych celach, z zachowaniem tekstu licencji.
- **Użycie komercyjne** (firma, usługi dla klientów, płatny produkt) wymaga pisemnej zgody
  autora: <https://github.com/s29829>. Szczegóły: `LICENSE-COMMERCIAL.md` w repozytorium.

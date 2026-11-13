# Changelog - Security Guard

Numeracja wtyczki: 1.00, 1.01, 1.02 … (+0.01 przy każdej zmianie, `tools/release.py bump`).
Wersja wtyczki w `security_guard.yaml`; wersja całego repozytorium w pliku `VERSION` (zob. `CHANGELOG.md` w katalogu głównym).

## [1.03] - 2026-11-13
- Dokumentacja: instalacja na Apache (Ubuntu/Debian i rodzina RHEL) – użytkownik i grupa uruchamiające PHP (mod_php / PHP-FPM), uprawnienia, wyłączenie listowania katalogów (Options -Indexes), SELinux; odpowiedniki reguł nginx dla Apache (ServerTokens, SimpleSAMLphp, ukryte pliki, mod_remoteip, limity).

## [1.02] - 2026-11-13
- Powiadomienia o incydentach bezpieczeństwa do wskazanych użytkowników i grup użytkowników: powiadomienie ResourceSpace i/lub e-mail, wybór rodzajów incydentów (zablokowane ataki, ataki na logowanie, usuwanie wielu zasobów, wykrycia bez blokady, zmiany Security Guard), ograniczenie częstotliwości (na regułę i adres oraz na godzinę), powiadomienie testowe, zmiany ustawień w logu; pozycja w kontroli konfiguracji.

## [1.01] - 2026-11-13
- Ochrona przed usuwaniem: wymuszony kosz ($resource_deletion_state), limity usuwania na użytkownika i okres (z resource_log) dla API, usuwania kolekcji z zasobami i edycji zbiorczej do stanu Deleted, trwałe usuwanie w przeglądarce w ramach limitu albo zablokowane, powyżej limitu zatwierdzenie przez innego administratora (cztery oczy, powiadomienia, zatwierdzanie z góry, wycofywanie zgód); polityka udostępniania: wymagane hasło, proponowane losowe hasło o minimalnej długości, domyślny i maksymalny okres ważności egzekwowany na serwerze, opcjonalnie bez zmiany daty i bez „Never”.

## [1.00] - 2026-11-13
- Pierwsza wersja: wirtualne łatki (daty raportów tylko liczbowe, przekierowanie po logowaniu tylko w serwisie, jedno źródło nazwy funkcji w API, blokada logowania przez API, sesja tylko z ciasteczka, opcjonalnie jedna sesja na konto), SimpleSAMLphp (ukrycie szczegółów błędów, lokalny panel logowania: open/allowlist/block, limit prób), lekki firewall (zaufane proxy, blokowane adresy, strony admina i klucze API tylko z listy IP, blokowanie skanerów, wzorce ataków: log/block), nagłówki (bez X-Powered-By, Permissions-Policy), log bezpieczeństwa dla fail2ban, kontrola konfiguracji, szablony nginx/fail2ban, wyłączniki awaryjne, Reset plugin.


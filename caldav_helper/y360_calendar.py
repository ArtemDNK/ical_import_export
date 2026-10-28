import csv
import glob
import html
import json
import logging
import logging.handlers as handlers
import os
import re
import sys
import time
import uuid
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from datetime import datetime, date, timedelta, timezone
from http import HTTPStatus
from typing import Optional, TextIO
from urllib.parse import urljoin, quote, unquote, urlparse
import concurrent.futures
import threading
import traceback

import requests
from dotenv import load_dotenv
from requests.auth import HTTPBasicAuth

import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

DEFAULT_HTTP_TIMEOUT_SEC = 60


def _ssl_verify_enabled() -> bool:
    # По умолчанию проверка SSL отключена (корпоративный прокси с самоподписанным сертификатом).
    # Включается параметром SSL_VERIFY=true в .env.
    return os.environ.get("SSL_VERIFY", "false").lower() == "true"


# Глобальные умолчания для всех запросов requests: verify (см. выше) и таймаут —
# без таймаута зависший сервер блокирует поток навсегда.
_orig_session_request = requests.Session.request


def _patched_session_request(self, method, url, **kwargs):
    kwargs.setdefault("verify", _ssl_verify_enabled())
    kwargs.setdefault("timeout", DEFAULT_HTTP_TIMEOUT_SEC)
    return _orig_session_request(self, method, url, **kwargs)


requests.Session.request = _patched_session_request

DEFAULT_360_API_URL = "https://api360.yandex.net"
DEFAULT_OAUTH_API_URL = "https://oauth.yandex.ru/token"
CALDAV_BASE_URL = "https://caldav.yandex.ru"
#CALDAV_BASE_URL = "https://post.udmr.ru/caldav"

LOG_FILE = "y360_calendar.log"
MAX_RETRIES = 3
RETRIES_DELAY_SEC = 2
SLEEP_TIME_BETWEEN_API_CALLS = 0.5
USERS_PER_PAGE_FROM_API = 1000
DOMAINS_PER_PAGE_FROM_API = 10   # maximum allowed by API

DEFAULT_OUTPUT_MAX_MB = 9
DEFAULT_THREADS = 4
ALL_USERS_REFRESH_IN_MINUTES = 15
RPS_LIMIT = 100
_last_call_caldav = 0.0
_rate_limit_lock = threading.Lock()
_users_cache_lock = threading.Lock()
_domains_cache_lock = threading.Lock()

# Маппинг Windows-имён часовых зон (Exchange) → IANA (Яндекс CalDAV).
# Яндекс CalDAV может отклонять с 400 нестандартные TZID, особенно
# в повторяющихся событиях с RECURRENCE-ID.
WINDOWS_TO_IANA_TZID: dict[str, str] = {
    "Russian Standard Time": "Europe/Moscow",
    "North Asia Standard Time": "Asia/Krasnoyarsk",
    "Kaliningrad Standard Time": "Europe/Kaliningrad",
    "E. Europe Standard Time": "Europe/Chisinau",
    "FLE Standard Time": "Europe/Kiev",
    "GTB Standard Time": "Europe/Bucharest",
    "Turkey Standard Time": "Europe/Istanbul",
    "Ekaterinburg Standard Time": "Asia/Yekaterinburg",
    "N. Central Asia Standard Time": "Asia/Novosibirsk",
    "North Asia East Standard Time": "Asia/Irkutsk",
    "Yakutsk Standard Time": "Asia/Yakutsk",
    "Vladivostok Standard Time": "Asia/Vladivostok",
    "Magadan Standard Time": "Asia/Magadan",
    "Kamchatka Standard Time": "Asia/Kamchatka",
    "Caucasus Standard Time": "Asia/Yerevan",
    "Georgian Standard Time": "Asia/Tbilisi",
    "Azerbaijan Standard Time": "Asia/Baku",
    "Central Asia Standard Time": "Asia/Almaty",
    "West Asia Standard Time": "Asia/Tashkent",
    "China Standard Time": "Asia/Shanghai",
    "Singapore Standard Time": "Asia/Singapore",
    "Tokyo Standard Time": "Asia/Tokyo",
    "Korea Standard Time": "Asia/Seoul",
    "India Standard Time": "Asia/Kolkata",
    "Central European Standard Time": "Europe/Warsaw",
    "W. Europe Standard Time": "Europe/Berlin",
    "Romance Standard Time": "Europe/Paris",
    "GMT Standard Time": "Europe/London",
    "Greenwich Standard Time": "Atlantic/Reykjavik",
    "Eastern Standard Time": "America/New_York",
    "Central Standard Time": "America/Chicago",
    "Mountain Standard Time": "America/Denver",
    "Pacific Standard Time": "America/Los_Angeles",
    "US Mountain Standard Time": "America/Phoenix",
    "Atlantic Standard Time": "America/Halifax",
    "UTC": "UTC",
    "Altai Standard Time": "Asia/Barnaul",
    "Astrakhan Standard Time": "Europe/Astrakhan",
    "Belarus Standard Time": "Europe/Minsk",
    "Russia Time Zone 3": "Europe/Samara",
    "Russia Time Zone 10": "Asia/Srednekolymsk",
    "Russia Time Zone 11": "Asia/Kamchatka",
    "Sakhalin Standard Time": "Asia/Sakhalin",
    "Tomsk Standard Time": "Asia/Tomsk",
    "Transbaikal Standard Time": "Asia/Chita",
    "Omsk Standard Time": "Asia/Omsk",
    "Saratov Standard Time": "Europe/Saratov",
    "Volgograd Standard Time": "Europe/Volgograd",
}


def is_verbose_logging_enabled() -> bool:
    return os.environ.get("VERBOSE_LOGGING", "false").lower() == "true"

# Required permissions for OAuth token (API user list access)
NEEDED_PERMISSIONS = [
    "directory:read_users",
    "directory:read_domains",
    "ya360_admin:mail_read_routing_rules",
    "ya360_admin:mail_write_routing_rules"
]

SERVICE_APP_PERMISSIONS = [
    "calendar:all"
]

EXIT_CODE = 1

# ─────────────────────── Правила обработки почты (Mail Routing Rules) ───────────────────────

CALDAV_EVENT_CANCEL_DROP_RULE = {
    "terminal": False,
    "condition": {
        "$and": [
            {
                "header:X-Calendar-Action-Source": {
                    "$eq": "CALDAV"
                }
            },
            {
                "header:X-Calendar-Mail-Type": {
                    "$eq": "event_cancel"
                }
            }
        ]
    },
    "actions": [
        {
            "action": "drop"
        }
    ],
    "scope": {
        "direction": "inbound"
    }
}

logger = logging.getLogger(LOG_FILE)
logger.setLevel(logging.DEBUG)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(
    logging.Formatter(
        "%(asctime)s.%(msecs)03d %(levelname)s:\t%(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
)
file_handler = handlers.RotatingFileHandler(
    LOG_FILE, maxBytes=1024 * 1024 * 10, backupCount=5, encoding="utf-8"
)
file_handler.setLevel(logging.DEBUG)
file_handler.setFormatter(
    logging.Formatter(
        "%(asctime)s.%(msecs)03d %(levelname)s:\t%(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
)
logger.addHandler(console_handler)
logger.addHandler(file_handler)


@dataclass
class SettingParams:
    oauth_token: str
    org_id: int
    users_file: str
    dry_run: bool
    service_app_id: str
    service_app_secret: str
    input_dir: str
    output_dir: str
    reports_dir: str
    output_max_mb: int
    threads: int
    modify_rules: str
    rule_apply_report: str
    all_users: list
    all_users_get_timestamp: datetime
    all_domains: list
    all_domains_get_timestamp: datetime
    service_app_status: bool
    routing_rules_file: str
    create_cancel_rules_for_events_deletions: bool
    external_caldav_users_file: str
    external_caldav_url: str
    service_app_api_data_file: str
    user_mapping_file: str
    

class TokenError(RuntimeError):
    pass


def get_settings() -> Optional[SettingParams]:
    exit_flag = False
    oauth_token_bad = False
    settings = SettingParams(
        users_file=os.environ.get("USERS_FILE", "users.csv"),
        oauth_token=os.environ.get("OAUTH_TOKEN"),
        org_id=os.environ.get("ORG_ID"),
        dry_run=os.environ.get("DRY_RUN", "false").lower() == "true",
        service_app_id=os.environ.get("SERVICE_APP_ID"),
        service_app_secret=os.environ.get("SERVICE_APP_SECRET"),
        input_dir=os.environ.get("INPUT_DIR", "input"),
        output_dir=os.environ.get("OUTPUT_DIR", "output"),
        reports_dir=os.environ.get("REPORTS_DIR", "reports"),
        output_max_mb=int(os.environ.get("OUTPUT_MAX_MB", DEFAULT_OUTPUT_MAX_MB)),
        threads=int(os.environ.get("THREADS", DEFAULT_THREADS)),
        modify_rules=os.environ.get("MODIFY_RULES", "ical_modify_rules.txt"),
        rule_apply_report=os.environ.get("RULE_APPLY_REPORT", "rule_apply.csv"),
        all_users=[],
        all_users_get_timestamp=datetime.now(),
        all_domains=[],
        all_domains_get_timestamp=datetime.now(),
        service_app_status=False,
        routing_rules_file=os.environ.get("ROUTING_RULES_FILE", "routing_rules.json"),
        create_cancel_rules_for_events_deletions=os.environ.get("CREATE_CANCEL_RULES_FOR_EVENTS_DELETIONS", "false").lower() == "true",
        external_caldav_users_file=os.environ.get("EXTERNAL_CALDAV_USERS_FILE", "external_caldav_users.csv"),
        external_caldav_url=os.environ.get("EXTERNAL_CALDAV_URL", ""),
        service_app_api_data_file=os.environ.get("SERVICE_APP_API_DATA_FILE", "service_app_api_data.json"),
        user_mapping_file=os.environ.get("USER_MAPPING_FILE", "user_mapping.txt"),
    )

    if not settings.users_file:
        logger.error("USERS_FILE не установлен.")
        exit_flag = True
    if not settings.oauth_token:
        logger.error("OAUTH_TOKEN не установлен.")
        oauth_token_bad = True
    if not settings.org_id:
        logger.error("ORG_ID не установлен.")
        exit_flag = True
    if not settings.service_app_id:
        logger.error("SERVICE_APP_ID не установлен.")
        exit_flag = True
    if not settings.service_app_secret:
        logger.error("SERVICE_APP_SECRET не установлен.")
        exit_flag = True

    if not (oauth_token_bad or exit_flag):
        hard_error, result_ok = check_token_permissions(
            settings.oauth_token, settings.org_id, NEEDED_PERMISSIONS
        )
        if hard_error:
            logger.error(
                "OAUTH_TOKEN не является действительным или не имеет необходимых прав доступа"
            )
            oauth_token_bad = True
        elif not result_ok:
            print(
                "ВНИМАНИЕ: Функциональность скрипта может быть ограничена. "
                "Возможны ошибки при работе с API."
            )
            print("=" * 100)
            input("Нажмите Enter для продолжения..")

    if oauth_token_bad:
        return None

    check_service_app_status(settings, skip_permissions_check=True)
    if not settings.service_app_status:
        logger.error("Сервисное приложение не настроено. Настройте сервисное приложение через меню настроек.")
 

    return None if exit_flag else settings


def check_token_permissions(
    token: str, org_id: int, needed_permissions: list
) -> tuple[bool, bool]:
    """
    Проверяет права доступа для заданного токена.

    Returns:
        bool: True если токен невалидный, False в противном случае
        bool: True если все права присутствуют и org_id совпадает, False в противном случае
    """
    url = "https://api360.yandex.net/whoami"
    headers = {"Authorization": f"OAuth {token}"}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code != HTTPStatus.OK:
            logger.error(f"Невалидный токен. Статус код: {response.status_code}")
            if response.status_code == 401:
                logger.error("Токен недействителен или истек срок его действия.")
            else:
                logger.error(f"Ошибка при проверке токена: {response.text}")
            return True, False

        data = response.json()
        token_scopes = data.get("scopes", [])
        token_org_ids = data.get("orgIds", [])
        login = data.get("login", "unknown")

        logger.info(f"Проверка прав доступа для токена пользователя: {login}")
        logger.debug(f"Доступные права: {token_scopes}")
        logger.debug(f"Доступные организации: {token_org_ids}")

        if str(org_id) not in [str(org) for org in token_org_ids]:
            logger.error("=" * 100)
            logger.error(
                f"ОШИБКА: Токен не имеет доступа к организации с ID {org_id}"
            )
            logger.error(
                f"Доступные организации для этого токена: {token_org_ids}"
            )
            logger.error("=" * 100)
            return True, False

        missing_permissions = [
            permission
            for permission in needed_permissions
            if permission not in token_scopes
        ]
        if missing_permissions:
            logger.error("=" * 100)
            logger.error("ОШИБКА: У токена отсутствуют необходимые права доступа!")
            logger.error("Недостающие права:")
            for perm in missing_permissions:
                logger.error(f"  - {perm}")
            logger.error("=" * 100)
            return False, False

        logger.info("✓ Все необходимые права доступа присутствуют")
        logger.info(f"✓ Доступ к организации {org_id} подтвержден")
        return False, True

    except requests.exceptions.RequestException as exc:
        logger.error(f"Ошибка при выполнении запроса к API: {exc}")
        return True, False
    except json.JSONDecodeError as exc:
        logger.error(f"Ошибка при парсинге ответа от API: {exc}")
        return True, False
    except Exception as exc:
        logger.error(
            f"Неожиданная ошибка при проверке прав доступа: {type(exc).__name__}: {exc}"
        )
        return True, False


def get_service_app_token(settings: "SettingParams", user_email: str) -> str:
    client_id = settings.service_app_id
    client_secret = settings.service_app_secret

    if not client_id or not client_secret:
        raise TokenError("SERVICE_APP_ID and SERVICE_APP_SECRET must be set")

    data = {
        "grant_type": "urn:ietf:params:oauth:grant-type:token-exchange",
        "client_id": client_id,
        "client_secret": client_secret,
        "subject_token": user_email,
        "subject_token_type": "urn:yandex:params:oauth:token-type:email",
    }

    try:
        response = requests.post(DEFAULT_OAUTH_API_URL, data=data, timeout=30)
    except requests.RequestException as exc:
        raise TokenError(f"Failed to request token: {exc}") from exc

    if not response.ok:
        raise TokenError(
            f"Token request failed for {user_email}: {response.status_code} {response.text}"
        )

    payload = response.json()
    access_token = payload.get("access_token")
    if not access_token:
        raise TokenError(f"No access_token in response for {user_email}: {payload}")
    return access_token


def read_users_csv(path: str) -> list[str]:
    if not os.path.exists(path):
        logger.error(f"Users file not found: {path}")
        return []

    with open(path, newline="", encoding="utf-8-sig") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    data_list = []
    for row in rows:
        email = row.get("Email") or row.get("email") or row.get("EMAIL")
        if email:
            data_list.append(email.strip().lower())
    return data_list

def read_external_caldav_users_csv(path: str) -> list[dict]:
    """
    Читает пользователей для подключения к внешнему CalDAV-серверу из csv-файла со схемой:
    alias;login;password
    Пропускает строки начинающиеся с '#'
    Возвращает список словарей {alias, login, password}
    """
    if not os.path.exists(path):
        logger.error(f"External CalDAV users file not found: {path}")
        return []

    data_list = []
    header_skipped = False
    with open(path, newline="", encoding="utf-8-sig") as f:
        # Обработка строк вручную, чтобы поддерживать комментарии
        for line_num, raw_line in enumerate(f, start=1):
            line = raw_line.strip()
            if not line or line.startswith('#'):
                continue
            if not header_skipped:
                # первая значимая строка - всегда заголовок, пропустить
                header_skipped = True
                continue
            # maxsplit=2: пароль может содержать ';'
            parts = line.split(";", 2)
            if len(parts) != 3:
                logger.warning(f"External CalDAV users: строка {line_num} пропущена (ожидается alias;login;password)")
                continue
            alias, login, password = (p.strip() for p in parts)
            data_list.append({"alias": alias, "login": login, "password": password})
    return data_list


def get_all_api360_users(settings: "SettingParams", force: bool = False) -> list[dict]:
    if not force:
        logger.info("Getting all users of the organisation from cache...")

    # Блокировка: при параллельном импорте потоки одновременно видели устаревший кэш
    # и каждый заново выгружал весь список пользователей из API.
    with _users_cache_lock:
        if (
            not settings.all_users
            or force
            or (datetime.now() - settings.all_users_get_timestamp).total_seconds()
            > ALL_USERS_REFRESH_IN_MINUTES * 60
        ):
            logger.info("Getting all users of the organisation from API...")
            settings.all_users = get_all_api360_users_from_api(settings)
            settings.all_users_get_timestamp = datetime.now()
        return settings.all_users


def get_all_api360_users_from_api(settings: "SettingParams") -> list[dict]:
    logger.info("Получение всех пользователей организации из API...")
    url = f"{DEFAULT_360_API_URL}/directory/v1/org/{settings.org_id}/users"
    users = []
    current_page = 1
    last_page = 1
    with requests.Session() as session:
        session.headers.update({"Authorization": f"OAuth {settings.oauth_token}"})
        while current_page <= last_page:
            params = {"page": current_page, "perPage": USERS_PER_PAGE_FROM_API}
            try:
                retries = 1
                while True:
                    response = session.get(url, params=params)
                    if response.status_code != HTTPStatus.OK.value:
                        logger.error(
                            f"Ошибка при GET запросе url - {url}: {response.status_code}. {response.text}"
                        )
                        if retries < MAX_RETRIES:
                            logger.error(f"Повторная попытка ({retries + 1}/{MAX_RETRIES})")
                            time.sleep(RETRIES_DELAY_SEC * retries)
                            retries += 1
                        else:
                            return []
                    else:
                        for user in response.json().get("users", []):
                            if not user.get("isRobot"):
                                users.append(user)
                        current_page += 1
                        last_page = response.json().get("pages", current_page)
                        break
            except requests.exceptions.RequestException as exc:
                logger.error(f"RequestException: {exc}")
                return []

    return users

def get_all_api360_domains(settings: "SettingParams", force: bool = False) -> list[dict]:
    if not force:
        logger.info("Getting all domains of the organisation from cache...")

    with _domains_cache_lock:
        if (
            not settings.all_domains
            or force
            or (datetime.now() - settings.all_domains_get_timestamp).total_seconds()
            > ALL_USERS_REFRESH_IN_MINUTES * 60
        ):
            logger.info("Getting all domains of the organisation from API...")
            settings.all_domains = get_all_api360_domains_from_api(settings)
            settings.all_domains_get_timestamp = datetime.now()
        return settings.all_domains


def get_all_api360_domains_from_api(settings: "SettingParams") -> list[dict]:
    logger.info("Получение всех доменов организации из API...")
    url = f"{DEFAULT_360_API_URL}/directory/v1/org/{settings.org_id}/domains"
    domains = []
    current_page = 1
    last_page = 1
    with requests.Session() as session:
        session.headers.update({"Authorization": f"OAuth {settings.oauth_token}"})
        while current_page <= last_page:
            params = {"page": current_page, "perPage": DOMAINS_PER_PAGE_FROM_API}
            try:
                retries = 1
                while True:
                    response = session.get(url, params=params)
                    if response.status_code != HTTPStatus.OK.value:
                        logger.error(
                            f"Ошибка при GET запросе url - {url}: {response.status_code}. {response.text}"
                        )
                        if retries < MAX_RETRIES:
                            logger.error(f"Повторная попытка ({retries + 1}/{MAX_RETRIES})")
                            time.sleep(RETRIES_DELAY_SEC * retries)
                            retries += 1
                        else:
                            return []
                    else:
                        for domain in response.json().get("domains", []):
                            if domain.get("verified"):
                                domains.append(domain)
                        current_page += 1
                        last_page = response.json().get("pages", current_page)
                        break
            except requests.exceptions.RequestException as exc:
                logger.error(f"RequestException: {exc}")
                return []

    return domains

def get_all_users_unique_aliases(settings: "SettingParams") -> set[str]:
    # set, а не list: используется для проверки вхождения на каждое импортируемое событие
    users = get_all_api360_users(settings)
    unique_aliases = set()
    for user in users:
        unique_aliases.add(user.get("nickname", "").lower())
        for alias in user.get("aliases", []):
            unique_aliases.add(alias.lower())
    unique_aliases.discard("")
    return unique_aliases

def find_users_prompt(
    settings: "SettingParams", answer: str = ""
) -> tuple[list[dict], bool, bool, bool]:
    break_flag = False
    double_users_flag = False
    users_to_add: list[dict] = []
    all_users_flag = False
    print('\nВведите пользователей в Яндекс 360 (алиасы, uid, фамилия), разделённые запятой или пробелом.')
    print('* - все пользователи, ! - загрузить из файла, Enter - выход в меню.\n')
    if not answer:
        answer = input('Пользователи: ')

    if not answer.strip():
        break_flag = True
        return users_to_add, break_flag, double_users_flag, all_users_flag

    users = get_all_api360_users(settings)
    if not users:
        logger.info("No users found in Y360 organization.")
        break_flag = True
        return users_to_add, break_flag, double_users_flag, all_users_flag

    if answer.strip() == "*":
        all_users_flag = True
        return users, break_flag, double_users_flag, all_users_flag

    search_users: list[str] = []
    if answer.strip() == "!":
        search_users = read_users_csv(settings.users_file)
        if not search_users:
            logger.info(f"No users found in file {settings.users_file}.")
            break_flag = True
            return users_to_add, break_flag, double_users_flag, all_users_flag

    if not search_users:
        pattern = r"[;,\s]+"
        search_users = re.split(pattern, answer)

    for searched in search_users:
        if not searched:
            continue
        if "@" in searched.strip():
            searched = searched.split("@")[0]
        found_flag = False
        if all(char.isdigit() for char in searched.strip()):
            for user in users:
                if user.get("id") == searched.strip():
                    users_to_add.append(user)
                    found_flag = True
                    break
        else:
            found_last_name_user = []
            for user in users:
                aliases_lower_case = [r.lower() for r in user.get("aliases", [])]
                if user.get("nickname", "").lower() == searched.lower().strip() or (
                    searched.lower().strip() in aliases_lower_case
                ):
                    users_to_add.append(user)
                    found_flag = True
                    break
                if user.get("name", {}).get("last", "").lower() == searched.lower().strip():
                    found_last_name_user.append(user)
            if not found_flag and found_last_name_user:
                if len(found_last_name_user) == 1:
                    users_to_add.append(found_last_name_user[0])
                    found_flag = True
                else:
                    logger.error(f"User {searched} found more than one user:")
                    for user in found_last_name_user:
                        logger.error(
                            f" - last name {user.get('name', {}).get('last')}, nickname {user.get('nickname')} ({user.get('id')}, {user.get('position')})"
                        )
                    logger.error("Refine your search parameters.")
                    double_users_flag = True
                    break

        if not found_flag:
            logger.error(f"User {searched} not found in Y360 organization.")
      

    return users_to_add, break_flag, double_users_flag, all_users_flag

def get_external_caldav_users_prompt(
    settings: "SettingParams"
) -> tuple[list[dict], bool]:

    break_flag = False    
    users_to_add: list[dict] = []
    
    print('\nВведите информацию о подключению к внешнему серверу CalDAV.')
    print('формат <CALDAV_логин>:<CALDAV_пароль>, ! - загрузить из файла, Enter - выход в меню.\n')
    answer = input('Данные о подключении: ')

    if not answer.strip():
        break_flag = True
        return users_to_add, break_flag

    if answer.strip() == "!":
        users_to_add = read_external_caldav_users_csv(settings.external_caldav_users_file)
        if not users_to_add:
            logger.error(f"Не найдены пользователи для обработки в файле {settings.external_caldav_users_file}.")
        return users_to_add, break_flag

    # maxsplit=1: пароль может содержать ':'
    one_user = answer.strip().split(":", 1)
    if len(one_user) != 2 or not one_user[0] or not one_user[1]:
        logger.error("Неверный формат данных о подключении. Используйте формат <CALDAV_login>:<CALDAV_password>.")
        return users_to_add, break_flag

    # Заменяем потенциальные спецсимволы (/, \, @) в логине на подчёркивание
    login_clean = re.sub(r'[\\/ @]', '_', one_user[0])
    users_to_add.append({"alias": login_clean, "login": one_user[0], "password": one_user[1]})

    return users_to_add, break_flag


def parse_date_input(value: str) -> Optional[datetime]:
    if not value:
        return None
    value = value.strip()
    if not value:
        return None
    if re.match(r"^[+-]\d+[dDwWmMyY]$", value):
        amount = int(value[:-1])
        unit = value[-1].lower()
        now = datetime.now()
        if unit == "d":
            return now + timedelta(days=amount)
        if unit == "w":
            return now + timedelta(weeks=amount)
        if unit == "m":
            return add_months(now, amount)
        if unit == "y":
            return add_months(now, amount * 12)
    for fmt in ("%Y-%m-%d", "%d.%m.%Y", "%d/%m/%Y", "%y-%m-%d", "%d.%m.%y", "%d/%m/%y", "%Y%m%d", "%y%m%d"):
        try:
            return datetime.strptime(value, fmt)
        except ValueError:
            continue
    raise ValueError("Invalid date format. Use YYYY-MM-DD, DD.MM.YYYY, DD/MM/YYYY (year as YYYY or YY), or offset.")


def add_months(base: datetime, months: int) -> datetime:
    year = base.year + (base.month - 1 + months) // 12
    month = (base.month - 1 + months) % 12 + 1
    day = min(base.day, days_in_month(year, month))
    return base.replace(year=year, month=month, day=day)


def days_in_month(year: int, month: int) -> int:
    next_month = date(year, month, 28) + timedelta(days=4)
    return (next_month - timedelta(days=next_month.day)).day


def build_thread_prefix(thread_id: int) -> str:
    return f"[T{thread_id}] "


def rate_limit_caldav_commands() -> None:
    """Глобальный лимит RPS для CalDAV-запросов из всех потоков.

    Раньше функция не была потокобезопасной: несколько потоков одновременно читали
    одно и то же время последнего вызова и лимит фактически не соблюдался.
    Теперь каждый вызов под блокировкой резервирует свой слот, а спит вне её.
    """
    global _last_call_caldav
    min_interval = 1.0 / RPS_LIMIT
    with _rate_limit_lock:
        now = time.monotonic()
        slot = max(now, _last_call_caldav + min_interval)
        _last_call_caldav = slot
    delay = slot - now
    if delay > 0:
        time.sleep(delay)


# Разбиение только по CR/LF: str.splitlines() режет ещё и по \x0b, \x0c, \x1c-\x1e,
# \x85,  ,  , которые встречаются внутри текстов событий (Outlook)
# и раньше разрывали свойство на несколько «строк».
_ICAL_LINE_SPLIT_RE = re.compile(r"\r\n|\n|\r")


def _split_ical_lines(text: str) -> list[str]:
    lines = _ICAL_LINE_SPLIT_RE.split(text)
    if lines and lines[-1] == "":
        lines.pop()
    return lines


def _unfold_ical_lines(text: str) -> list[str]:
    unfolded: list[str] = []
    for line in _split_ical_lines(text):
        if line.startswith((" ", "\t")) and unfolded:
            unfolded[-1] += line[1:]
        else:
            unfolded.append(line)
    return unfolded


def _fold_ical_lines(text: str, max_octets: int = 75) -> str:
    """Re-fold long lines per RFC 5545.

    Lines longer than *max_octets* bytes (UTF-8) are split by inserting
    a line break followed by a single space character.  The first chunk
    keeps the original content up to *max_octets* bytes; every subsequent
    continuation chunk is prefixed with a space and carries up to
    *max_octets - 1* bytes of payload so that total line width (including
    the leading space) never exceeds *max_octets*.
    """
    result: list[str] = []
    for line in _split_ical_lines(text):
        encoded = line.encode("utf-8")
        if len(encoded) <= max_octets:
            result.append(line)
            continue
        # First chunk: up to max_octets bytes
        first_chunk = _safe_utf8_slice(encoded, max_octets)
        result.append(first_chunk)
        remaining = encoded[len(first_chunk.encode("utf-8")):]
        # Continuation chunks: space + up to (max_octets - 1) bytes
        while remaining:
            chunk = _safe_utf8_slice(remaining, max_octets - 1)
            result.append(f" {chunk}")
            remaining = remaining[len(chunk.encode("utf-8")):]
    return "\n".join(result)


def _safe_utf8_slice(data: bytes, max_bytes: int) -> str:
    """Decode up to *max_bytes* from *data* without splitting a multi-byte character."""
    if max_bytes >= len(data):
        return data.decode("utf-8")
    cut = max_bytes
    # Step back if we're in the middle of a multi-byte UTF-8 sequence
    while cut > 0 and (data[cut] & 0xC0) == 0x80:
        cut -= 1
    return data[:cut].decode("utf-8")


def _extract_vevent_blocks(ics_text: str) -> list[str]:
    lines = _unfold_ical_lines(ics_text)
    events = []
    current: list[str] = []
    in_event = False
    for line in lines:
        if line.strip() == "BEGIN:VEVENT":
            in_event = True
            current = [line]
            continue
        if line.strip() == "END:VEVENT" and in_event:
            current.append(line)
            events.append("\n".join(current))
            in_event = False
            current = []
            continue
        if in_event:
            current.append(line)
    return events


def _extract_vtimezone_blocks(ics_text: str) -> list[str]:
    lines = _unfold_ical_lines(ics_text)
    blocks = []
    current: list[str] = []
    in_tz = False
    for line in lines:
        if line.strip() == "BEGIN:VTIMEZONE":
            in_tz = True
            current = [line]
            continue
        if line.strip() == "END:VTIMEZONE" and in_tz:
            current.append(line)
            blocks.append("\n".join(current))
            in_tz = False
            current = []
            continue
        if in_tz:
            current.append(line)
    return blocks


def _extract_tzid_from_vtimezone(vtimezone_text: str) -> Optional[str]:
    """Извлекает TZID из блока VTIMEZONE."""
    for line in _unfold_ical_lines(vtimezone_text):
        if line.upper().startswith("TZID:"):
            return line.split(":", 1)[1].strip()
    return None


def _collect_referenced_tzids(vevent_texts: list[str]) -> set[str]:
    """Собирает все TZID, на которые ссылаются VEVENT-блоки.

    Ищет параметр TZID= в свойствах DTSTART, DTEND, RECURRENCE-ID и т.д.
    """
    tzids: set[str] = set()
    tzid_re = re.compile(r'TZID=([^;:]+)', re.IGNORECASE)
    for ev in vevent_texts:
        for line in _unfold_ical_lines(ev):
            for m in tzid_re.finditer(line):
                tzids.add(m.group(1).strip().strip('"'))
    return tzids


def _filter_vtimezones_by_reference(
    vtimezones: list[str], referenced_tzids: set[str]
) -> list[str]:
    """Оставляет только VTIMEZONE-блоки, на которые ссылаются события.

    Также учитывает маппинг WINDOWS_TO_IANA_TZID: если ссылка
    была нормализована, включает VTIMEZONE по IANA-имени.
    """
    if not referenced_tzids:
        return []
    filtered = []
    for tz_block in vtimezones:
        tzid = _extract_tzid_from_vtimezone(tz_block)
        if tzid and tzid in referenced_tzids:
            filtered.append(tz_block)
    return filtered


def _is_guid_tzid(tzid: str) -> bool:
    """Проверяет, является ли TZID GUID-ом (Exchange иногда генерирует такие)."""
    # Типичный GUID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
    return bool(re.match(
        r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
        tzid, re.IGNORECASE
    ))


def _resolve_windows_tzid(tzid: str) -> Optional[str]:
    """Возвращает IANA-эквивалент Windows-имени TZID или None, если не нужна замена.

    Обрабатывает:
      - Прямое совпадение по WINDOWS_TO_IANA_TZID
      - GUID-based TZID (пытаемся определить по смещению)
      - Имена вида "(UTC+07:00) Krasnoyarsk"
    """
    if tzid in WINDOWS_TO_IANA_TZID:
        return WINDOWS_TO_IANA_TZID[tzid]
    # Уже IANA — замена не нужна
    if "/" in tzid or tzid == "UTC":
        return None
    # GUID — без контекста смещения не можем конвертировать, вернём None
    if _is_guid_tzid(tzid):
        return None
    # "(UTC+07:00) Krasnoyarsk" — пробуем извлечь смещение
    m = re.match(r'^\(UTC([+-]\d{2}:\d{2})\)\s*(.+)$', tzid)
    if m:
        offset_str, city_hint = m.group(1), m.group(2).strip()
        # Пробуем найти по городу в маппинге (проверяем и Windows-имя, и IANA-имя)
        for win_name, iana_name in WINDOWS_TO_IANA_TZID.items():
            if city_hint.lower() in win_name.lower() or city_hint.lower() in iana_name.lower():
                return iana_name
        # Fallback по смещению: "+07:00" → "+0700"
        compact_offset = offset_str.replace(":", "")
        iana = _iana_from_utc_offset(compact_offset)
        if iana:
            return iana
    return None


def _normalize_tzids_in_text(text: str, tzid_map: dict[str, str]) -> str:
    """Заменяет все вхождения старого TZID на новый в iCal-тексте.

    Обрабатывает:
      - TZID=<old> в свойствах (DTSTART, DTEND, RECURRENCE-ID и т.д.)
      - TZID:<old> в VTIMEZONE
    """
    for old_tzid, new_tzid in tzid_map.items():
        old_re = re.escape(old_tzid)
        # TZID=... (в параметрах свойств) — с учётом возможных кавычек.
        # Значение должно заканчиваться на ':' или ';' — иначе простая замена подстроки
        # портила TZID с общим префиксом (например, "Russia Time Zone 1" и "... 10").
        text = re.sub(
            rf'TZID=(?:"{old_re}"|{old_re})(?=[;:])',
            lambda _m, v=new_tzid: f"TZID={v}",
            text,
        )
        # TZID:... (определение в VTIMEZONE) — значение до конца строки
        text = re.sub(
            rf"^TZID:{old_re}[ \t]*(?=\r?$)",
            lambda _m, v=new_tzid: f"TZID:{v}",
            text,
            flags=re.MULTILINE,
        )
    return text


def _normalize_event_group_tzids(
    event_group: list[str], vtimezones: list[str]
) -> tuple[list[str], list[str]]:
    """Нормализует Windows-style TZID → IANA в событиях и VTIMEZONE-блоках.

    Returns:
        (normalized_events, normalized_vtimezones)
    """
    # 1. Собираем все TZID, используемые в группе событий
    referenced = _collect_referenced_tzids(event_group)

    # 2. Строим маппинг замен для нестандартных TZID
    tzid_replace_map: dict[str, str] = {}
    for tzid in referenced:
        replacement = _resolve_windows_tzid(tzid)
        if replacement:
            tzid_replace_map[tzid] = replacement

    # 3. Обработка GUID TZID: находим смещение из VTIMEZONE и подбираем IANA
    for tzid in list(referenced):
        if _is_guid_tzid(tzid) and tzid not in tzid_replace_map:
            # Ищем VTIMEZONE для этого GUID и берём смещение
            for tz_block in vtimezones:
                block_tzid = _extract_tzid_from_vtimezone(tz_block)
                if block_tzid == tzid:
                    offset = _extract_utc_offset_from_vtimezone(tz_block)
                    if offset:
                        iana = _iana_from_utc_offset(offset)
                        if iana:
                            tzid_replace_map[tzid] = iana
                    break

    if tzid_replace_map:
        logger.debug(f"Normalizing TZIDs: {tzid_replace_map}")

    # 4. Применяем замены к событиям
    normalized_events = []
    for ev in event_group:
        normalized_events.append(_normalize_tzids_in_text(ev, tzid_replace_map))

    # 5. Нормализуем и фильтруем VTIMEZONE-блоки
    normalized_tz = []
    for tz_block in vtimezones:
        normalized_tz.append(_normalize_tzids_in_text(tz_block, tzid_replace_map))

    # 6. Пересобираем referenced после нормализации
    final_referenced = _collect_referenced_tzids(normalized_events)
    filtered_tz = _filter_vtimezones_by_reference(normalized_tz, final_referenced)

    # 7. Дедупликация VTIMEZONE по TZID (после замены могут появиться дубли)
    seen_tzids: set[str] = set()
    deduped_tz: list[str] = []
    for tz_block in filtered_tz:
        tzid = _extract_tzid_from_vtimezone(tz_block)
        if tzid and tzid not in seen_tzids:
            seen_tzids.add(tzid)
            deduped_tz.append(tz_block)

    return normalized_events, deduped_tz


def _extract_utc_offset_from_vtimezone(vtimezone_text: str) -> Optional[str]:
    """Извлекает TZOFFSETTO из STANDARD секции VTIMEZONE."""
    in_standard = False
    for line in _unfold_ical_lines(vtimezone_text):
        stripped = line.strip().upper()
        if stripped == "BEGIN:STANDARD":
            in_standard = True
        elif stripped == "END:STANDARD":
            in_standard = False
        elif in_standard and stripped.startswith("TZOFFSETTO:"):
            return line.split(":", 1)[1].strip()
    return None


def _iana_from_utc_offset(offset: str) -> Optional[str]:
    """Подбирает наиболее вероятный IANA TZID по UTC-смещению.

    Используется как fallback для GUID и нестандартных TZID.
    """
    offset_to_iana = {
        "+0200": "Europe/Kaliningrad",
        "+0300": "Europe/Moscow",
        "+0400": "Europe/Samara",
        "+0500": "Asia/Yekaterinburg",
        "+0600": "Asia/Omsk",
        "+0700": "Asia/Krasnoyarsk",
        "+0800": "Asia/Irkutsk",
        "+0900": "Asia/Yakutsk",
        "+1000": "Asia/Vladivostok",
        "+1100": "Asia/Srednekolymsk",
        "+1200": "Asia/Kamchatka",
        "+0000": "UTC",
        "-0500": "America/New_York",
        "-0600": "America/Chicago",
        "-0700": "America/Denver",
        "-0800": "America/Los_Angeles",
        "+0100": "Europe/Berlin",
        "+0530": "Asia/Kolkata",
    }
    return offset_to_iana.get(offset)


def _extract_uid_from_event(vevent_text: str) -> Optional[str]:
    for line in _unfold_ical_lines(vevent_text):
        if line.upper().startswith("UID:"):
            return line.split(":", 1)[1].strip()
    return None


def _has_recurrence_id(vevent_text: str) -> bool:
    """Проверяет наличие RECURRENCE-ID в VEVENT (это исключение из повторяющегося события)."""
    for line in _unfold_ical_lines(vevent_text):
        if line.upper().startswith("RECURRENCE-ID"):
            return True
    return False


def _group_events_by_uid(events: list[str]) -> dict[str, list[str]]:
    """Группирует VEVENT-блоки по UID.

    Мастер-событие (без RECURRENCE-ID) идёт первым в списке.
    Одиночные события (без RRULE и без RECURRENCE-ID) попадают
    в группу из одного элемента.

    Returns:
        dict[str, list[str]]: UID → список VEVENT-блоков (мастер первым).
    """
    groups: dict[str, list[str]] = {}
    order: list[str] = []          # для сохранения порядка первого появления UID
    for ev in events:
        uid = _extract_uid_from_event(ev)
        if not uid:
            # Событие без UID — сохраняем под уникальным ключом
            uid = f"__no_uid_{id(ev)}"
        if uid not in groups:
            order.append(uid)
            groups[uid] = []
        groups[uid].append(ev)
    # Сортировка внутри группы: мастер (без RECURRENCE-ID) первым
    for uid, evs in groups.items():
        evs.sort(key=lambda e: (1 if _has_recurrence_id(e) else 0))
    # Возвращаем OrderedDict-подобный обычный dict (Python 3.7+)
    return {uid: groups[uid] for uid in order}


def _recurrence_id_value(vevent_text: str) -> str:
    for line in _unfold_ical_lines(vevent_text):
        if _get_ical_tag_name(line) == "recurrence-id" and ":" in line:
            return line.split(":", 1)[1].strip()
    return ""


def _group_layer_events(
    layer_events: list[tuple[str, str]],
) -> tuple[dict[str, list[str]], dict[str, str], int]:
    """Группирует события слоя (из всех его файлов) по UID.

    Args:
        layer_events: список (путь_к_файлу, VEVENT).

    Returns:
        (группы UID -> VEVENT-ы с мастером первым,
         UID -> файл, в котором группа встретилась впервые (для отчёта),
         количество отброшенных дубликатов).

    Дубликаты (тот же UID и тот же RECURRENCE-ID, например повторная выгрузка того же
    календаря) отбрасываются: два мастера с одним UID в одном PUT сервер отвергает.
    """
    unique_events: list[str] = []
    event_files: dict[int, str] = {}
    seen: set[tuple[str, str]] = set()
    duplicates = 0
    for file_path, ev in layer_events:
        uid = _extract_uid_from_event(ev)
        if uid:
            key = (uid, _recurrence_id_value(ev))
            if key in seen:
                duplicates += 1
                continue
            seen.add(key)
        event_files[id(ev)] = file_path
        unique_events.append(ev)

    groups = _group_events_by_uid(unique_events)
    group_files = {uid: event_files[id(evs[0])] for uid, evs in groups.items()}
    return groups, group_files, duplicates


def _replace_uid_in_event(vevent_text: str, new_uid: str) -> str:
    lines = _unfold_ical_lines(vevent_text)
    updated = []
    replaced = False
    for line in lines:
        if line.upper().startswith("UID:") and not replaced:
            updated.append(f"UID:{new_uid}")
            replaced = True
        else:
            updated.append(line)
    if not replaced:
        updated.insert(1, f"UID:{new_uid}")
    return "\n".join(updated)


def _parse_ical_datetime_value(value: str) -> Optional[datetime]:
    """Разбирает значение DATE / DATE-TIME. При некорректном значении возвращает None
    (раньше ValueError из strptime ронял поток импорта/выгрузки целиком)."""
    value = value.strip()
    try:
        if len(value) == 8:
            return datetime.strptime(value, "%Y%m%d")
        if value.endswith("Z"):
            return datetime.strptime(value, "%Y%m%dT%H%M%SZ")
        if len(value) >= 15:
            return datetime.strptime(value[:15], "%Y%m%dT%H%M%S")
    except ValueError:
        logger.debug(f"Не удалось разобрать дату iCal: '{value}'")
    return None


def _extract_datetime_property(vevent_text: str, prop_name: str) -> Optional[datetime]:
    for line in _unfold_ical_lines(vevent_text):
        if _get_ical_tag_name(line) != prop_name or ":" not in line:
            continue
        return _parse_ical_datetime_value(line.split(":", 1)[1])
    return None


def _extract_dtstart(vevent_text: str) -> Optional[datetime]:
    return _extract_datetime_property(vevent_text, "dtstart")


def _extract_dtend(vevent_text: str) -> Optional[datetime]:
    return _extract_datetime_property(vevent_text, "dtend")


def _extract_summary(vevent_text: str) -> str:
    for line in _unfold_ical_lines(vevent_text):
        upper = line.upper()
        if upper.startswith("SUMMARY:") or upper.startswith("SUMMARY;"):
            return line.split(":", 1)[1].strip()
    return ""


def build_vcalendar(vevent_text, vtimezones: list[str]) -> str:
    """Оборачивает один или несколько VEVENT-блоков в VCALENDAR.

    Args:
        vevent_text: один VEVENT-блок (str) **или** список VEVENT-блоков (list[str]).
                     Список используется для повторяющихся событий с исключениями
                     (мастер + RECURRENCE-ID блоки).
        vtimezones:  список VTIMEZONE-блоков.
    """
    parts = [
        "BEGIN:VCALENDAR",
        "VERSION:2.0",
        "PRODID:-//y360_calendar//EN",
        "X-YANDEX-SKIP-INVITATION-EMAILS:true",
    ]
    parts.extend(vtimezones)
    if isinstance(vevent_text, list):
        parts.extend(vevent_text)
    else:
        parts.append(vevent_text)
    parts.append("END:VCALENDAR")
    return _fold_ical_lines("\n".join(parts)) + "\n"


def match_with_wildcard(pattern: str, text: str) -> bool:
    if not pattern or not text:
        return False
    escaped = re.escape(pattern)
    wildcard_pattern = escaped.replace(r"\*", ".*")
    regex_pattern = f"^{wildcard_pattern}$"
    try:
        return bool(re.match(regex_pattern, text, re.IGNORECASE))
    except re.error:
        return False


def match_email_with_template(template: str, email: str) -> bool:
    if not template or not email:
        return False
    template = template.lower().strip()
    email = email.lower().strip()
    if "@" not in email:
        return False
    email_local, email_domain = email.split("@", 1)
    if "@" in template:
        if template.count("@") != 1:
            return False
        template_local, template_domain = template.split("@", 1)
        if not match_with_wildcard(template_local, email_local):
            return False
        if not match_with_wildcard(template_domain, email_domain):
            return False
    else:
        if not match_with_wildcard(template, email_domain):
            return False
    return True


def replace_email_with_template(
    search_template: str, replace_template: str, email: str
) -> Optional[str]:
    if not search_template or not replace_template or not email:
        return None

    search_template = search_template.strip().lower()
    replace_template = replace_template.strip().lower()
    email_original = email.strip()
    email_lower = email_original.lower()

    if not match_email_with_template(search_template, email_lower):
        return None

    if "@" not in email_lower:
        return None
    email_local, email_domain = email_lower.split("@", 1)

    escaped = re.escape(search_template)
    escaped_star = r'\*'
    search_regex = f"^{escaped.replace(escaped_star, '(.+?)')}$"
    captured_groups: list[str] = []
    try:
        search_match = re.match(search_regex, email_lower, re.IGNORECASE)
        if search_match:
            captured_groups = list(search_match.groups())
    except re.error:
        return None

    result_parts: list[str] = []
    before_at = True
    captured_index = 0
    for ch in replace_template:
        if ch == "*":
            if captured_index < len(captured_groups):
                replacement_value = captured_groups[captured_index]
                captured_index += 1
            else:
                replacement_value = email_local if before_at else email_domain
            result_parts.append(replacement_value)
        else:
            if ch == "@":
                before_at = False
            result_parts.append(ch)
    new_email = "".join(result_parts)
    if new_email == email_lower:
        return None
    return new_email


def load_modify_rules(settings: "SettingParams") -> list[tuple[str, str, str, str]]:
    """Load iCal modification rules from file.

    File format: first line is header (tag;operator;value1;value2),
    remaining lines are rules.
    Returns list of (tag, operator, value1, value2) tuples.
    """
    rules: list[tuple[str, str, str, str]] = []
    rules_file = settings.modify_rules
    if not rules_file:
        return rules
    if not os.path.exists(rules_file):
        logger.warning(f"Modify rules file not found: {rules_file}")
        return rules
    try:
        with open(rules_file, encoding="utf-8-sig") as f:
            lines = f.readlines()
    except OSError as exc:
        logger.error(f"Failed to read modify rules file {rules_file}: {exc}")
        return rules
    if len(lines) < 2:
        return rules
    for line_text in lines[1:]:
        line_text = line_text.strip()
        if not line_text or line_text.startswith("#"):
            continue
        # maxsplit=3: value2 (строка замены regex) может содержать ';'
        parts = line_text.split(";", 3)
        if len(parts) < 3:
            logger.warning(f"Invalid modify rule (not enough fields): {line_text}")
            continue
        tag = parts[0].strip().lower()
        operator = parts[1].strip().lower()
        value1 = parts[2].strip() if len(parts) > 2 else ""
        value2 = parts[3].strip() if len(parts) > 3 else ""
        if operator == "add":
            email_re = r"^[^@\s]+@[^@\s]+\.[^@\s.]+(\.[^@\s.]+){0,2}$"
            if not (re.match(email_re, value1) or re.match(email_re, value2)):
                logger.warning(f"Skipping 'add' rule (no valid email in value1 or value2): {line_text}")
                continue
        rules.append((tag, operator, value1, value2))
    if rules:
        logger.info(f"Loaded {len(rules)} modify rule(s) from {rules_file}:")
        for idx, (tag, operator, value1, value2) in enumerate(rules, start=1):
            logger.debug(f"  Rule {idx}: tag={tag}, operator={operator}, value1={value1}, value2={value2}")
    else:
        logger.info(f"No modify rules found in {rules_file}")
    return rules


def _get_ical_tag_name(line: str) -> str:
    """Extract the iCal property name from a line.

    Examples:
        'CLASS:PUBLIC' -> 'class'
        'SUMMARY;LANGUAGE=ru-RU:text' -> 'summary'
        'ATTENDEE;ROLE=REQ-PARTICIPANT;...:mailto:...' -> 'attendee'
        'ORGANIZER;CN=...:MAILTO:...' -> 'organizer'
    """
    for i, ch in enumerate(line):
        if ch in (":", ";"):
            return line[:i].lower()
    return line.lower()


def _apply_class_replace(line: str, value1: str, value2: str) -> str:
    """Replace CLASS value (PUBLIC <-> PRIVATE)."""
    if ":" not in line:
        return line
    prefix, current_value = line.split(":", 1)
    if current_value.strip().upper() == value1.upper():
        return f"{prefix}:{value2.upper()}"
    return line


def _apply_summary_replace(line: str, value1: str, value2: str) -> str:
    """Replace text in SUMMARY value using regex.

    Line format: SUMMARY:text or SUMMARY;LANGUAGE=ru-RU:text
    value1 is the search regex, value2 is the replacement.
    """
    if ":" not in line:
        return line
    colon_pos = line.index(":")
    prefix = line[:colon_pos]
    text = line[colon_pos + 1:]
    try:
        new_text = re.sub(value1, value2, text)
    except re.error as exc:
        logger.warning(f"Invalid regex in SUMMARY replace rule '{value1}': {exc}")
        return line
    return f"{prefix}:{new_text}"


def _is_email_pattern(value: str) -> bool:
    """Check if the pattern looks like an email pattern (contains @)."""
    return "@" in value


def _apply_attendee_or_organizer_replace(line: str, value1: str, value2: str) -> str:
    """Replace email or CN in ATTENDEE/ORGANIZER line.

    If value1 contains '@', replaces email after 'mailto:' using wildcard
    templates (e.g. *@yandry.*, romans@*.ru).
    Otherwise replaces CN value (after 'CN=' and before the next ':' or ';')
    using regex.
    """
    if _is_email_pattern(value1):
        mailto_match = re.search(r"(mailto:)([\S]+)", line, re.IGNORECASE)
        if not mailto_match:
            return line
        mailto_prefix = mailto_match.group(1)
        email = mailto_match.group(2)
        new_email = replace_email_with_template(value1, value2, email)
        if new_email:
            return line[:mailto_match.start()] + mailto_prefix + new_email + line[mailto_match.end():]
        return line
    else:
        cn_pattern = re.compile(r"(CN=)([^:;]+)", re.IGNORECASE)

        def cn_replacer(match: re.Match) -> str:
            cn_prefix = match.group(1)
            cn_value = match.group(2)
            try:
                new_cn = re.sub(value1, value2, cn_value)
            except re.error as exc:
                logger.warning(
                    f"Invalid regex in CN replace rule '{value1}': {exc}"
                )
                return match.group(0)
            return f"{cn_prefix}{new_cn}"

        return cn_pattern.sub(cn_replacer, line)


def _should_delete_attendee(line: str, delete_rules: list[tuple[str, str, str, str]]) -> bool:
    """Check if an ATTENDEE line should be deleted based on delete rules.

    Matches value1 wildcard template (e.g. *@yandry.*, romans@*.ru)
    against the email after 'mailto:' in the line.
    """
    mailto_match = re.search(r"mailto:([\S]+)", line, re.IGNORECASE)
    if not mailto_match:
        return False
    email = mailto_match.group(1)
    for _, _, value1, _ in delete_rules:
        if match_email_with_template(value1, email):
            return True
    return False


def _find_matching_delete_rule(
    line: str, delete_rules: list[tuple[str, str, str, str]]
) -> Optional[tuple[str, str, str, str]]:
    """Find the first matching delete rule for an ATTENDEE line.

    Returns the matching rule tuple or None.
    """
    mailto_match = re.search(r"mailto:([\S]+)", line, re.IGNORECASE)
    if not mailto_match:
        return None
    email = mailto_match.group(1)
    for rule in delete_rules:
        _, _, value1, _ = rule
        if match_email_with_template(value1, email):
            return rule
    return None


def _format_rule_text(tag: str, operator: str, value1: str, value2: str) -> str:
    """Format a rule tuple as a text string like in ical_modify_rules.txt."""
    if value2:
        return f"{tag};{operator};{value1};{value2}"
    return f"{tag};{operator};{value1}"


def _parse_add_rule(value1: str, value2: str) -> Optional[tuple[str, str]]:
    """Parse add rule values into (email, cn_name).

    value1 and value2 can be in any order: one must be a valid email,
    the other is the CN name (optional).
    Returns (email, cn_name) or None if no valid email found.
    """
    email = ""
    cn_name = ""
    if "@" in value1:
        email = value1.strip()
        cn_name = value2.strip()
    elif "@" in value2:
        email = value2.strip()
        cn_name = value1.strip()
    if not email:
        return None
    return email, cn_name


def _build_attendee_line(email: str, cn_name: str) -> str:
    """Build an ATTENDEE line in iCal format.

    Format: ATTENDEE;ROLE=REQ-PARTICIPANT;PARTSTAT=NEEDS-ACTION;CN=<name>:mailto:<email>
    """
    if cn_name:
        return f"ATTENDEE;ROLE=REQ-PARTICIPANT;PARTSTAT=NEEDS-ACTION;CN={cn_name}:mailto:{email}"
    return f"ATTENDEE;ROLE=REQ-PARTICIPANT;PARTSTAT=NEEDS-ACTION:mailto:{email}"


def modify_ics_content(
    ics_text: str, rules: list[tuple[str, str, str, str]]
) -> tuple[str, list[tuple[str, str, str]]]:
    """Modify iCal content according to rules.

    Each rule is (tag, operator, value1, value2).
    Supported tags: class, summary, attendee, organizer.
    Supported operators: replace, delete, add.
    For delete: tag must be 'attendee' (or '*'), value1 is email wildcard template.
    For add: tag must be 'attendee' (or '*'), value1/value2 are email and CN name
    (in any order, email is required).

    Returns (modified_text, changes) where changes is a list of
    (rule_text, old_value, new_value) tuples.
    For delete rules old_value is the deleted line, new_value is empty.
    For add rules old_value is empty, new_value is the added line.
    """
    changes: list[tuple[str, str, str]] = []
    if not rules:
        return ics_text, changes

    replace_rules = [(tag, op, v1, v2) for tag, op, v1, v2 in rules if op == "replace"]
    delete_rules = [
        (tag, op, v1, v2)
        for tag, op, v1, v2 in rules
        if op == "delete" and tag in ("attendee", "*")
    ]
    add_rules = [
        (tag, op, v1, v2)
        for tag, op, v1, v2 in rules
        if op == "add" and tag in ("attendee", "*")
    ]

    if not replace_rules and not delete_rules and not add_rules:
        return ics_text, changes

    # Unfold RFC 5545 continuation lines (lines starting with space/tab
    # are continuations of the previous line and must be joined)
    lines = _unfold_ical_lines(ics_text)

    # Split ICS into segments: non-VEVENT lines and individual VEVENT blocks
    segments: list[tuple[str, list[str]]] = []
    current_segment: list[str] = []
    in_vevent = False

    for line in lines:
        stripped = line.strip()
        if stripped == "BEGIN:VEVENT":
            if current_segment:
                segments.append(("other", current_segment))
                current_segment = []
            in_vevent = True
            current_segment.append(line)
        elif stripped == "END:VEVENT" and in_vevent:
            current_segment.append(line)
            segments.append(("vevent", current_segment))
            current_segment = []
            in_vevent = False
        else:
            current_segment.append(line)

    if current_segment:
        segments.append(("other", current_segment))

    # Process each VEVENT through the full cycle of modifications independently
    result_lines: list[str] = []
    for seg_type, seg_lines in segments:
        if seg_type != "vevent":
            result_lines.extend(seg_lines)
            continue

        event_lines = seg_lines

        # Pass 1: delete
        if delete_rules:
            after_delete = []
            for line in event_lines:
                tag_name = _get_ical_tag_name(line)
                if tag_name == "attendee":
                    matched_rule = _find_matching_delete_rule(line, delete_rules)
                    if matched_rule:
                        rule_text = _format_rule_text(*matched_rule)
                        changes.append((rule_text, line, ""))
                        continue
                after_delete.append(line)
            event_lines = after_delete

        # Pass 2: replace
        if replace_rules:
            after_replace = []
            for line in event_lines:
                modified_line = line
                tag_name = _get_ical_tag_name(line)
                for rule_tag, op, value1, value2 in replace_rules:
                    if rule_tag != tag_name:
                        continue
                    before_rule = modified_line
                    if tag_name == "class":
                        modified_line = _apply_class_replace(modified_line, value1, value2)
                    elif tag_name == "summary":
                        modified_line = _apply_summary_replace(modified_line, value1, value2)
                    elif tag_name in ("attendee", "organizer"):
                        modified_line = _apply_attendee_or_organizer_replace(
                            modified_line, value1, value2
                        )
                    if modified_line != before_rule:
                        rule_text = _format_rule_text(rule_tag, op, value1, value2)
                        changes.append((rule_text, before_rule, modified_line))
                after_replace.append(modified_line)
            event_lines = after_replace

        # Pass 3: add
        if add_rules:
            # Collect all existing participant emails (attendees + organizer)
            existing_emails = set()
            for line in event_lines:
                tag_name = _get_ical_tag_name(line)
                if tag_name in ("attendee", "organizer"):
                    mailto_match = re.search(r"mailto:([\S]+)", line, re.IGNORECASE)
                    if mailto_match:
                        existing_emails.add(mailto_match.group(1).lower())
            after_add = []
            for line in event_lines:
                if line.strip() == "END:VEVENT":
                    for tag, op, v1, v2 in add_rules:
                        parsed = _parse_add_rule(v1, v2)
                        if not parsed:
                            logger.warning(f"Invalid add rule: no email found in '{v1}', '{v2}'")
                            continue
                        add_email, add_cn = parsed
                        if add_email.lower() in existing_emails:
                            continue
                        new_line = _build_attendee_line(add_email, add_cn)
                        after_add.append(new_line)
                        existing_emails.add(add_email.lower())
                        rule_text = _format_rule_text(tag, op, v1, v2)
                        changes.append((rule_text, "", new_line))
                after_add.append(line)
            event_lines = after_add

        result_lines.extend(event_lines)

    return _fold_ical_lines("\n".join(result_lines)), changes


def build_caldav_session(user_email: str, token: str) -> requests.Session:
    session = requests.Session()
    session.auth = HTTPBasicAuth(user_email, token)
    session.headers.update({"User-Agent": "y360_calendar/1.0"})
    return session


def _refresh_caldav_session(
    session: requests.Session, settings: "SettingParams", user_email: str
) -> requests.Session:
    """Перевыпускает токен сервисного приложения после 401 и закрывает старую сессию."""
    token = get_service_app_token(settings, user_email)
    session.close()
    return build_caldav_session(user_email, token)


def _caldav_propfind(session: requests.Session, url: str, body: str, depth: str = "0") -> requests.Response:
    headers = {"Depth": depth, "Content-Type": "application/xml; charset=utf-8"}
    rate_limit_caldav_commands()
    if is_verbose_logging_enabled():
        logger.debug(f"CalDAV request url={url} headers={headers} body={body}")
    try:
        response = session.request("PROPFIND", url, headers=headers, data=body, timeout=30)
    except requests.exceptions.ConnectionError as exc:
        logger.error(f"CalDAV connection error for {url}: {exc}")
        raise
    except requests.exceptions.Timeout as exc:
        logger.error(f"CalDAV request timeout for {url}: {exc}")
        raise
    except requests.exceptions.RequestException as exc:
        logger.error(f"CalDAV request failed for {url}: {exc}")
        raise
    if is_verbose_logging_enabled():
        response_text = response.content.decode("utf-8", errors="replace")
        logger.debug(
            f"CalDAV response status_code={response.status_code} text={response_text}"
        )
    return response


DAV_NS = "{DAV:}"
CALDAV_NS = "{urn:ietf:params:xml:ns:caldav}"
_HTTP_STATUS_RE = re.compile(r"\s(\d{3})(?:\s|$)")


def _xml_local_name(tag) -> str:
    if not isinstance(tag, str):
        return ""
    return tag.rsplit("}", 1)[-1]


def _parse_xml(content) -> Optional[ET.Element]:
    """Разбирает XML-ответ CalDAV-сервера.

    Раньше ответы разбирались регулярными выражениями по литеральным префиксам
    <D:response>, <D:href>, <C:calendar-data>. Серверы, использующие другие префиксы
    (d:, cal:, пространство имён по умолчанию), возвращали «пустой» результат,
    а XML-сущности (&amp;, &lt;, &#13;) не декодировались и попадали в выгружаемые .ics.
    """
    if not content:
        return None
    try:
        return ET.fromstring(content)
    except ET.ParseError as exc:
        logger.error(f"Не удалось разобрать XML-ответ CalDAV: {exc}")
        return None


def _status_code(status_text: Optional[str]) -> str:
    """'HTTP/1.1 200 OK' -> '200'."""
    if not status_text:
        return ""
    match = _HTTP_STATUS_RE.search(" " + status_text.strip())
    return match.group(1) if match else ""


def _parse_multistatus(content) -> list[dict]:
    """Разбирает DAV:multistatus.

    Возвращает список {"href": str, "status": str, "props": {local_name: Element}},
    где props содержит только свойства из propstat со статусом 200 (или без статуса).
    """
    root = _parse_xml(content)
    if root is None:
        return []
    items = []
    for resp in root.iter(f"{DAV_NS}response"):
        href_el = resp.find(f"{DAV_NS}href")
        href = (href_el.text or "").strip() if href_el is not None else ""
        props: dict[str, ET.Element] = {}
        for propstat in resp.findall(f"{DAV_NS}propstat"):
            code = _status_code(propstat.findtext(f"{DAV_NS}status"))
            if code and code != "200":
                continue
            prop_el = propstat.find(f"{DAV_NS}prop")
            if prop_el is None:
                continue
            for prop in prop_el:
                props.setdefault(_xml_local_name(prop.tag), prop)
        items.append({
            "href": href,
            "status": _status_code(resp.findtext(f"{DAV_NS}status")),
            "props": props,
        })
    return items


def _prop_text(props: dict, name: str) -> Optional[str]:
    element = props.get(name)
    if element is None:
        return None
    return (element.text or "").strip()


def _find_nested_href(content, container_tag: str) -> Optional[str]:
    root = _parse_xml(content)
    if root is None:
        return None
    href_el = root.find(f".//{container_tag}/{DAV_NS}href")
    if href_el is None or not (href_el.text or "").strip():
        return None
    return href_el.text.strip()


def discover_calendar_home(user_email: str, session: requests.Session, external_caldav_url: Optional[str] = None) -> Optional[str]:
    propfind_root = """<?xml version='1.0'?>
<D:propfind xmlns:D="DAV:">
  <D:prop>
    <D:current-user-principal/>
  </D:prop>
</D:propfind>"""

    base_url = (external_caldav_url or CALDAV_BASE_URL).rstrip("/")

    root_candidates = [f"{base_url}/", f"{base_url}/.well-known/caldav"]
    principal_url = None
    for root_url in root_candidates:
        response = _caldav_propfind(session, root_url, propfind_root)
        if response.status_code not in (200, 207):
            logger.error(
                f"Failed to PROPFIND caldav root {root_url}: {response.status_code} {response.text}"
            )
            continue
        href = _find_nested_href(response.content, f"{DAV_NS}current-user-principal")
        if href:
            principal_url = urljoin(base_url + "/", href)
            break
    if not principal_url:
        encoded_email = quote(user_email.strip().lower())
        principal_url = f"{base_url}/principals/users/{encoded_email}/"

    propfind_principal = """<?xml version='1.0'?>
<D:propfind xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
  <D:prop>
    <C:calendar-home-set/>
  </D:prop>
</D:propfind>"""
    response = _caldav_propfind(session, principal_url, propfind_principal)
    if response.status_code not in (200, 207):
        logger.error(f"Failed to PROPFIND principal: {response.status_code} {response.text}")
        return None
    href = _find_nested_href(response.content, f"{CALDAV_NS}calendar-home-set")
    if not href:
        logger.error(f"calendar-home-set href not found in response for {principal_url}")
        return None
    return urljoin(base_url + "/", href)


def discover_calendars(calendar_home_url: str, session: requests.Session) -> list[dict]:
    propfind_books = """<?xml version='1.0'?>
<D:propfind xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav" xmlns:E="http://apple.com/ns/ical/" xmlns:CS="http://calendarserver.org/ns/">
  <D:prop>
      <D:resourcetype />
      <D:displayname />
      <CS:getctag />
      <E:calendar-color />
      <C:supported-calendar-component-set />
      <D:current-user-privilege-set />
  </D:prop>
</D:propfind>"""
    candidates = [calendar_home_url]
    if calendar_home_url.endswith("/"):
        candidates.append(calendar_home_url.rstrip("/"))
    else:
        candidates.append(calendar_home_url + "/")
    email_match = re.search(r"/calendars/([^/]+)/?", calendar_home_url)
    if email_match:
        encoded_email = email_match.group(1)
        decoded_email = unquote(encoded_email)
        if "@" in decoded_email:
            local, domain = decoded_email.split("@", 1)
            if domain.startswith("360."):
                alt_domain = domain[len("360."):]
            else:
                alt_domain = f"360.{domain}"
            alt_encoded = quote(f"{local}@{alt_domain}")
            candidates.append(calendar_home_url.replace(encoded_email, alt_encoded))

    response = None
    seen = set()
    for candidate_url in candidates:
        if candidate_url in seen:
            continue
        seen.add(candidate_url)
        try:
            response = _caldav_propfind(session, candidate_url, propfind_books, depth="1")
        except requests.RequestException as exc:
            logger.error(f"Failed to PROPFIND calendar home {candidate_url}: {exc}")
            continue
        if response.status_code in (200, 207):
            calendar_home_url = candidate_url
            break
        logger.error(
            f"PROPFIND {candidate_url} failed: {response.status_code} {response.text}"
        )

    if response is None or response.status_code not in (200, 207):
        return []

    calendars = []
    for item in _parse_multistatus(response.content):
        href_value = item["href"]
        if not href_value:
            continue
        # Skip inbox/outbox/notifications
        if any(
            part in href_value.lower()
            for part in ("/inbox/", "/outbox/", "/notifications/")
        ):
            continue

        props = item["props"]

        resourcetype = props.get("resourcetype")
        resource_names = (
            {_xml_local_name(child.tag).lower() for child in resourcetype}
            if resourcetype is not None else set()
        )
        is_calendar = "calendar" in resource_names

        component_set = props.get("supported-calendar-component-set")
        supports = []
        if component_set is not None:
            supports = [
                (comp.get("name") or "").upper()
                for comp in component_set
                if _xml_local_name(comp.tag) == "comp" and comp.get("name")
            ]

        # If has supported components (VEVENT/VTODO), it's a calendar
        if not is_calendar and {"VEVENT", "VTODO", "VJOURNAL"} & set(supports):
            is_calendar = True

        if not is_calendar:
            continue

        calendars.append(
            {
                "url": urljoin(calendar_home_url, href_value),
                "name": _prop_text(props, "displayname") or "Unknown",
                "components": supports,
                "color": _prop_text(props, "calendar-color"),
                "ctag": _prop_text(props, "getctag"),
            }
        )
    return calendars


def pick_default_personal_calendar(calendars: list[dict]) -> Optional[dict]:
    """
    Pick the default personal calendar for events.
    
    For Yandex CalDAV:
    - Calendars with events have URLs like /calendars/user/events-NNNN/
    - First calendar with VEVENT support is typically the default
    - Prefer calendars with "events-" in URL over todos-* calendars
    """
    if not calendars:
        return None
    
    # First, try to find calendars with VEVENT support and events- in URL
    event_calendars = [
        cal for cal in calendars
        if "VEVENT" in cal.get("components", []) and "events-" in cal.get("url", "")
    ]
    if event_calendars:
        return event_calendars[0]
    
    # Fall back to any calendar with VEVENT support
    for cal in calendars:
        if "VEVENT" in cal.get("components", []):
            return cal
    
    # Fall back to any calendar that's not todos/inbox/outbox
    for cal in calendars:
        url = cal.get("url", "").lower()
        if not any(part in url for part in ("todos-", "/inbox/", "/outbox/")):
            return cal
    
    return calendars[0] if calendars else None


def _to_caldav_utc(value: datetime) -> str:
    """Наивная дата из ввода пользователя — локальное время; CalDAV time-range ждёт UTC.

    Раньше локальное время просто помечалось суффиксом Z, и диапазон смещался
    на величину часового пояса.
    """
    if value.tzinfo is None:
        value = value.astimezone()
    return value.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def _event_href_name(uid: str) -> str:
    """Имя ресурса события в календаре: <uid>.ics с экранированием спецсимволов.

    Без экранирования UID вида "urn:uuid:..." превращался в urljoin() в абсолютный URL
    другой схемы, а '/', '?', '#', пробелы ломали путь.
    """
    return f"{quote(uid, safe='@-._~')}.ics"


def caldav_calendar_query(
    calendar_url: str,
    session: requests.Session,
    start: Optional[datetime],
    end: Optional[datetime],
    settings: Optional["SettingParams"] = None,
    user_email: Optional[str] = None,
) -> tuple[list[dict], requests.Session]:
    start_utc = _to_caldav_utc(start) if start else ""
    end_utc = _to_caldav_utc(end) if end else ""
    if start_utc and end_utc:
        time_range = f'<C:time-range start="{start_utc}" end="{end_utc}"/>'
    elif start_utc:
        time_range = f'<C:time-range start="{start_utc}"/>'
    elif end_utc:
        time_range = f'<C:time-range end="{end_utc}"/>'
    else:
        time_range = ""
    query = f"""<?xml version="1.0"?>
<C:calendar-query xmlns:C="urn:ietf:params:xml:ns:caldav">
  <D:prop xmlns:D="DAV:">
    <D:getetag/>
  </D:prop>
  <C:filter>
    <C:comp-filter name="VCALENDAR">
      <C:comp-filter name="VEVENT">
        {time_range}
      </C:comp-filter>
    </C:comp-filter>
  </C:filter>
</C:calendar-query>"""

    headers = {"Depth": "1", "Content-Type": "application/xml; charset=utf-8"}

    for attempt in range(1, MAX_RETRIES + 1):
        rate_limit_caldav_commands()
        if is_verbose_logging_enabled():
            logger.debug(f"CalDAV request url={calendar_url} headers={headers} body={query}")
        try:
            response = session.request(
                "REPORT",
                calendar_url,
                headers=headers,
                data=query,
                timeout=60,
            )
        except requests.exceptions.RequestException as exc:
            logger.error(f"CalDAV REPORT request error (attempt {attempt}/{MAX_RETRIES}): {exc}")
            if attempt < MAX_RETRIES:
                time.sleep(RETRIES_DELAY_SEC * attempt)
                continue
            return [], session

        if is_verbose_logging_enabled():
            response_text = response.content.decode("utf-8", errors="replace")
            logger.debug(
                f"CalDAV response status_code={response.status_code} text={response_text}"
            )

        if response.status_code in (200, 207):
            results = []
            for item in _parse_multistatus(response.content):
                if not item["href"]:
                    continue
                results.append(
                    {
                        "href": item["href"],
                        "etag": _prop_text(item["props"], "getetag") or None,
                    }
                )
            return results, session

        if response.status_code == 401 and settings and user_email:
            logger.warning(
                f"CalDAV REPORT auth error 401 (attempt {attempt}/{MAX_RETRIES}), refreshing session for {user_email}"
            )
            session = _refresh_caldav_session(session, settings, user_email)
            continue

        logger.error(
            f"Calendar query failed: status_code={response.status_code} (attempt {attempt}/{MAX_RETRIES})"
        )
        if attempt < MAX_RETRIES:
            time.sleep(RETRIES_DELAY_SEC * attempt)

    return [], session


def caldav_calendar_multiget(
    calendar_url: str, session: requests.Session, hrefs: list[str]
) -> list[dict]:
    if not hrefs:
        return []
    href_elements = "\n".join(f"<D:href>{html.escape(href, quote=False)}</D:href>" for href in hrefs)
    body = f"""<?xml version="1.0" encoding="utf-8"?>
<C:calendar-multiget xmlns:D="DAV:" xmlns:C="urn:ietf:params:xml:ns:caldav">
  <D:prop>
    <D:getetag/>
    <C:calendar-data/>
  </D:prop>
  {href_elements}
</C:calendar-multiget>"""
    rate_limit_caldav_commands()
    headers = {"Depth": "1", "Content-Type": "application/xml; charset=utf-8"}
    if is_verbose_logging_enabled():
        logger.debug(f"CalDAV request url={calendar_url} headers={headers} body={body}")
    try:
        response = session.request(
            "REPORT",
            calendar_url,
            headers=headers,
            data=body.encode("utf-8"),
            timeout=60,
        )
    except requests.exceptions.RequestException as exc:
        logger.error(f"Calendar multiget request error: {exc}")
        return []
    if is_verbose_logging_enabled():
        response_text = response.content.decode("utf-8", errors="replace")
        logger.debug(
            f"CalDAV response status_code={response.status_code} text={response_text}"
        )
    if response.status_code not in (200, 207):
        logger.error(f"Calendar multiget failed: {response.status_code} {response.text}")
        return []

    results = []
    for item in _parse_multistatus(response.content):
        if not item["href"]:
            continue
        calendar_data = _prop_text(item["props"], "calendar-data")
        if not calendar_data:
            continue
        results.append(
            {
                "href": item["href"],
                "etag": _prop_text(item["props"], "getetag") or None,
                "data": calendar_data.replace("\r\n", "\n").replace("\r", "\n"),
            }
        )
    return results


def caldav_find_event_by_uid(
    calendar_url: str, session: requests.Session, uid: str
) -> Optional[dict]:
    calendar_path = urlparse(calendar_url).path.rstrip("/")
    href_path = f"{calendar_path}/{_event_href_name(uid)}"
    multiget_query = f"""<?xml version="1.0"?>
<C:calendar-multiget xmlns:C="urn:ietf:params:xml:ns:caldav" xmlns:D="DAV:">
    <D:prop>
        <D:getetag/>
    </D:prop>
    <D:href>{html.escape(href_path, quote=False)}</D:href>
</C:calendar-multiget>"""
    rate_limit_caldav_commands()
    headers = {"Depth": "1", "Content-Type": "application/xml; charset=utf-8"}
    if is_verbose_logging_enabled():
        logger.debug(f"CalDAV request url={calendar_url} headers={headers} body={multiget_query}")
    try:
        response = session.request(
            "REPORT",
            calendar_url,
            headers=headers,
            data=multiget_query.encode("utf-8"),
            timeout=60,
        )
    except requests.exceptions.RequestException as exc:
        logger.error(f"CalDAV lookup by UID failed for {uid}: {exc}")
        return None
    if is_verbose_logging_enabled():
        response_text = response.content.decode("utf-8", errors="replace")
        logger.debug(
            f"CalDAV response status_code={response.status_code} text={response_text}"
        )
    if response.status_code not in (200, 207):
        return None
    for item in _parse_multistatus(response.content):
        etag = _prop_text(item["props"], "getetag")
        if item["href"] and etag and item["status"] in ("", "200"):
            return {"href": item["href"], "etag": etag}
    return None


def caldav_put_event(
    session: requests.Session,
    calendar_url: str,
    href: str,
    ical_data: str,
    etag: Optional[str] = None,
    create_only: bool = False,
    dry_run: bool = False,
    settings: Optional["SettingParams"] = None,
    user_email: Optional[str] = None,
) -> tuple[bool, requests.Session]:
    headers = {
        "Content-Type": "text/calendar; charset=utf-8",
        "X-YANDEX-SKIP-INVITATION-EMAILS": "true",
    }
    if etag:
        headers["If-Match"] = etag
    if create_only:
        headers["If-None-Match"] = "*"

    if dry_run:
        print(f"Dry run. Виртуальное создание события: {calendar_url} {href} {headers} {ical_data}")
        return True, session

    url = urljoin(calendar_url, href)

    for attempt in range(1, MAX_RETRIES + 1):
        rate_limit_caldav_commands()
        if is_verbose_logging_enabled():
            logger.debug(f"CalDAV request url={url} headers={headers} body={ical_data}")
        try:
            response = session.put(url, data=ical_data.encode("utf-8"), headers=headers, timeout=60)
        except requests.exceptions.RequestException as exc:
            logger.error(f"CalDAV PUT request error (attempt {attempt}/{MAX_RETRIES}): {exc}")
            if attempt < MAX_RETRIES:
                time.sleep(RETRIES_DELAY_SEC * attempt)
                continue
            return False, session

        if is_verbose_logging_enabled():
            response_text = response.content.decode("utf-8", errors="replace")
            logger.debug(
                f"CalDAV response status_code={response.status_code} text={response_text}"
            )

        if response.status_code in (200, 201, 204):
            return True, session

        if response.status_code == 401 and settings and user_email:
            logger.warning(
                f"CalDAV PUT auth error 401 (attempt {attempt}/{MAX_RETRIES}), refreshing session for {user_email}"
            )
            session = _refresh_caldav_session(session, settings, user_email)
            continue

        logger.error(
            f"CalDAV PUT error status_code={response.status_code} (attempt {attempt}/{MAX_RETRIES})"
        )
        if attempt < MAX_RETRIES:
            time.sleep(RETRIES_DELAY_SEC * attempt)

    return False, session


def caldav_delete_event(
    session: requests.Session,
    calendar_url: str,
    href: str,
    etag: Optional[str] = None,
    settings: Optional["SettingParams"] = None,
    user_email: Optional[str] = None,
) -> tuple[bool, requests.Session]:
    headers = {}
    if etag:
        headers["If-Match"] = etag

    url = urljoin(calendar_url, href)

    for attempt in range(1, MAX_RETRIES + 1):
        rate_limit_caldav_commands()
        if is_verbose_logging_enabled():
            logger.debug(f"CalDAV DELETE request url={url} headers={headers}")
        try:
            response = session.delete(url, headers=headers, timeout=60)
        except requests.exceptions.RequestException as exc:
            logger.error(f"CalDAV DELETE request error (attempt {attempt}/{MAX_RETRIES}): {exc}")
            if attempt < MAX_RETRIES:
                time.sleep(RETRIES_DELAY_SEC * attempt)
                continue
            return False, session

        if is_verbose_logging_enabled():
            response_text = response.content.decode("utf-8", errors="replace")
            logger.debug(
                f"CalDAV DELETE response status_code={response.status_code} text={response_text}"
            )

        if response.status_code in (200, 204):
            return True, session

        if response.status_code == 401 and settings and user_email:
            logger.warning(
                f"CalDAV DELETE auth error 401 (attempt {attempt}/{MAX_RETRIES}), refreshing session for {user_email}"
            )
            session = _refresh_caldav_session(session, settings, user_email)
            continue

        logger.error(
            f"CalDAV DELETE error status_code={response.status_code} (attempt {attempt}/{MAX_RETRIES})"
        )
        if attempt < MAX_RETRIES:
            time.sleep(RETRIES_DELAY_SEC * attempt)

    return False, session


def load_user_mapping(mapping_file: str) -> dict[str, str]:
    """Load user mapping from file. Returns dict {external_alias: y360_alias}.

    File format:
      - First line is header: external_email;y360_email
      - Lines starting with # are comments and skipped
      - Values can be email (alias@domain.com) or plain alias
      - Only the alias part (before @) is stored
    """
    mapping: dict[str, str] = {}
    if not os.path.isfile(mapping_file):
        logger.info(f"Файл user mapping '{mapping_file}' не найден, маппинг пользователей не используется.")
        return mapping

    try:
        with open(mapping_file, encoding="utf-8") as f:
            lines = f.readlines()
    except OSError as exc:
        logger.error(f"Не удалось прочитать файл user mapping '{mapping_file}': {exc}")
        return mapping

    if not lines:
        logger.warning(f"Файл user mapping '{mapping_file}' пуст.")
        return mapping

    for line_num, raw_line in enumerate(lines, start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line_num == 1 and line.lower() == "external_email;y360_email":
            continue
        parts = line.split(";")
        if len(parts) < 2:
            logger.warning(f"User mapping: строка {line_num} пропущена (ожидается два значения через ';'): {line}")
            continue
        ext_val = parts[0].strip()
        y360_val = parts[1].strip()
        if not ext_val or not y360_val:
            logger.warning(f"User mapping: строка {line_num} пропущена (пустое значение): {line}")
            continue
        ext_alias = ext_val.split("@")[0].lower() if "@" in ext_val else ext_val.lower()
        y360_alias = y360_val.split("@")[0].lower() if "@" in y360_val else y360_val.lower()
        mapping[ext_alias] = y360_alias

    if mapping:
        logger.info(f"User mapping загружен из '{mapping_file}': {len(mapping)} записей.")
        for ext_a, y360_a in mapping.items():
            logger.info(f"  User mapping: '{ext_a}' -> '{y360_a}'")
    else:
        logger.info(f"Файл user mapping '{mapping_file}' не содержит записей маппинга.")

    return mapping


def apply_user_mapping(
    files_map: dict[str, dict[str, list[str]]],
    user_mapping: dict[str, str],
) -> tuple[dict[str, dict[str, list[str]]], list[tuple[str, str]]]:
    """Apply user mapping to files_map keys. Returns updated files_map and list of applied substitutions.

    If an alias from files_map matches a key in user_mapping, the entry is
    re-keyed to the corresponding y360 alias.
    """
    if not user_mapping:
        return files_map, []

    applied: list[tuple[str, str]] = []
    new_map: dict[str, dict[str, list[str]]] = {}

    for alias, layers in files_map.items():
        target_alias = user_mapping.get(alias)
        if target_alias is not None:
            logger.info(f"User mapping: алиас из файла '{alias}' заменён на '{target_alias}'")
            applied.append((alias, target_alias))
            key = target_alias
        else:
            key = alias

        if key not in new_map:
            new_map[key] = {k: list(v) for k, v in layers.items()}
        else:
            existing = new_map[key]
            for layer_name, layer_files in layers.items():
                if layer_name in existing:
                    existing[layer_name].extend(layer_files)
                else:
                    existing[layer_name] = list(layer_files)

    if applied:
        logger.info(f"User mapping: выполнено замен алиасов: {len(applied)}")
    else:
        logger.info("User mapping: совпадений с алиасами из файлов не найдено.")

    return new_map, applied


def parse_input_files(input_dir: str) -> list[dict[str, list[dict[str, list[str]]]]]:
    """Parse input .ics files and group them by user alias and calendar layer.

    Filename format: user[~layer~][_YYMMDD_HHMMSS|_YYYYMMDD_HHMMSS][_N].ics
    where:
      - user: nickname (e.g. romans) or email (e.g. romans@yandry.ru);
        may contain underscores (e.g. user_01)
      - layer: calendar layer name, separated by ~; if wrapped in {}, it's the default layer
      - timestamp: optional, in YYMMDD_HHMMSS or YYYYMMDD_HHMMSS format;
        matched from the right so that underscores in the alias are preserved
      - N: optional file sequence number
    """
    if not os.path.isdir(input_dir):
        return []

    timestamp_re = re.compile(r'^(.+)_(\d{6,8}_\d{6})(?:_(\d+))?$')

    # Intermediate: alias -> layer_name -> [file_paths]
    data: dict[str, dict[str, list[str]]] = {}

    for name in os.listdir(input_dir):
        if not name.lower().endswith(".ics"):
            continue
        file_path = os.path.join(input_dir, name)
        base = name[:-4]  # remove .ics

        # Split by ~ to separate user, layer, and rest
        parts = base.split("~")

        if len(parts) >= 3:
            # user~layer~rest (rest is timestamp+seq)
            user_str = parts[0]
            layer_raw = "~".join(parts[1:-1])
        elif len(parts) == 2:
            # user~layer (no timestamp)
            user_str = parts[0]
            layer_raw = parts[1]
        else:
            # No layer: user[_timestamp[_seq]]
            user_str = parts[0]
            layer_raw = None
            # Strip timestamp+seq suffix from user string
            m = timestamp_re.match(user_str)
            if m:
                user_str = m.group(1)

        # Extract alias from user identifier
        if "@" in user_str:
            alias = user_str.split("@")[0].lower()
        else:
            alias = user_str.lower()

        if not alias:
            continue

        # Determine layer name
        if layer_raw is None:
            layer_name = "DEFAULT"
        elif layer_raw.startswith("{") and layer_raw.endswith("}") and len(layer_raw) > 2:
            # Wrapped in {} means it was the default layer in the source
            # account; map to the target account's default layer
            layer_name = "DEFAULT"
        else:
            layer_name = layer_raw

        data.setdefault(alias, {}).setdefault(layer_name, []).append(file_path)

    return data


def filter_events_by_date(
    events: list[str], start: Optional[datetime], end: Optional[datetime]
) -> list[str]:
    if not start and not end:
        return events
    filtered = []
    for ev in events:
        dtstart = _extract_dtstart(ev)
        if not dtstart:
            continue
        if start and dtstart < start:
            continue
        if end and dtstart > end:
            continue
        filtered.append(ev)
    return filtered


def _filter_event_groups_by_date(
    groups: dict[str, list[str]],
    start: Optional[datetime],
    end: Optional[datetime],
) -> dict[str, list[str]]:
    """Фильтрует группы событий по дате.

    Для групп с RRULE (повторяющееся событие) — включаем целиком,
    т.к. вхождения могут попадать в диапазон, даже если мастер — нет.
    Для обычных (одиночных) событий — стандартная фильтрация по DTSTART.
    """
    if not start and not end:
        return groups

    filtered: dict[str, list[str]] = {}
    for uid, evs in groups.items():
        master = evs[0] if evs else None
        if not master:
            continue
        # Если мастер имеет RRULE — включаем всю группу целиком
        if _event_has_rrule(master):
            filtered[uid] = evs
            continue
        # Иначе — включаем группу, если хоть одно событие попадает в диапазон
        any_match = False
        for ev in evs:
            dtstart = _extract_dtstart(ev)
            if not dtstart:
                continue
            if start and dtstart < start:
                continue
            if end and dtstart > end:
                continue
            any_match = True
            break
        if any_match:
            filtered[uid] = evs
    return filtered


def parse_event_properties(vevent_text: str) -> dict[str, list[str]]:
    props: dict[str, list[str]] = {}
    for line in _unfold_ical_lines(vevent_text):
        if ":" not in line:
            continue
        name, value = line.split(":", 1)
        name = name.split(";", 1)[0].upper()
        props.setdefault(name, []).append(value.strip())
    return props


def filter_events_by_query(events: list[str], query: str) -> list[str]:
    if not query:
        return events

    query = query.strip()
    filtered = []

    # "CLASS:<value>" case (strict full match)
    if " " not in query and ":" in query:
        tag, value = query.split(":", 1)
        tag = tag.strip().lower()
        value = value.strip().lower()
        for ev in events:
            props = parse_event_properties(ev)
            for k, vs in props.items():
                if k.lower() == tag:
                    for v in vs:
                        if v.strip().lower() == value:
                            filtered.append(ev)
                            break
                    else:
                        continue
                    break
        return filtered

    # "<TAG> contains <value>" case (tag contains value)
    parts = query.split(" ", 2)
    if len(parts) == 3:
        tag, operator, value = parts
        tag = tag.strip().lower()
        operator = operator.strip().lower()
        value = value.strip().lower()
        if operator == "contains":
            for ev in events:
                props = parse_event_properties(ev)
                for k, vs in props.items():
                    if k.lower() == tag:
                        for v in vs:
                            if value in v.strip().lower():
                                filtered.append(ev)
                                break
                        else:
                            continue
                        break
            return filtered

    logger.error("Некорректный формат фильтра. Используйте: CLASS:<value> или ORGANIZER contains <value>")
    return events


_FILENAME_INVALID_RE = re.compile(r'[<>:"/\\|?*\x00-\x1f~]')


def _safe_file_component(value: str) -> str:
    """Делает строку пригодной для имени файла. '~' тоже заменяется: это разделитель
    user~layer~timestamp в именах выгружаемых файлов (см. parse_input_files)."""
    cleaned = _FILENAME_INVALID_RE.sub("_", value).strip(" .")
    return cleaned or "_"


def _layer_file_name(calendar_name: str) -> str:
    return _safe_file_component(calendar_name.replace(" ", "_"))


def _write_ics_file(path: str, groups: list[list[str]], vtimezones: list[str]) -> None:
    events = [ev for group in groups for ev in group]
    with open(path, "w", encoding="utf-8") as f:
        f.write(build_vcalendar(events, vtimezones))


def export_events_for_user(
    settings: "SettingParams",
    user: dict,
    start: Optional[datetime],
    end: Optional[datetime],
    query_filter: str,
    thread_id: int = 0,
    external_caldav_url: Optional[str] = None,
) -> int:

    thread_prefix = build_thread_prefix(thread_id)

    # Если внешний сервер CalDAV не указан, используем токен сервисного приложения
    if not external_caldav_url:
        user_email = user.get("email")
        if not user_email:
            logger.warning(f"{thread_prefix}Skipping user without email.")
            return 0
        token = get_service_app_token(settings, user_email)
        # При 401 токен сервисного приложения можно перевыпустить
        refresh_settings = settings
    else:
        # Если внешний сервер CalDAV указан, используем логин и пароль из файла или ручного ввода
        token = user.get("password")
        if not token:
            logger.warning(f"{thread_prefix}Skipping user without password.")
            return 0
        user_email = user.get("login")
        if not user_email:
            logger.warning(f"{thread_prefix}Skipping user without login.")
            return 0
        # Для внешнего сервера 401 означает неверный пароль: перевыпуск токена Яндекса
        # (как было раньше) здесь бессмыслен и заканчивался TokenError.
        refresh_settings = None
    session = build_caldav_session(user_email, token)
    try:
        return _export_user_calendars(
            settings, session, user, user_email, start, end, query_filter,
            thread_prefix, external_caldav_url, refresh_settings,
        )
    finally:
        session.close()


def _export_user_calendars(
    settings: "SettingParams",
    session: requests.Session,
    user: dict,
    user_email: str,
    start: Optional[datetime],
    end: Optional[datetime],
    query_filter: str,
    thread_prefix: str,
    external_caldav_url: Optional[str],
    refresh_settings: Optional["SettingParams"],
) -> int:
    calendar_home = discover_calendar_home(user_email, session, external_caldav_url)
    if not calendar_home:
        logger.error(f"{thread_prefix}No calendar home for {user_email}")
        return 0

    calendars = discover_calendars(calendar_home, session)

    # Filter calendars that support VEVENT
    event_calendars = [
        cal for cal in calendars
        if "VEVENT" in cal.get("components", [])
    ]
    if not event_calendars:
        logger.warning(f"{thread_prefix}No calendar found for {user_email}")
        return 0

    default_calendar = pick_default_personal_calendar(calendars)

    try:
        os.makedirs(settings.output_dir, exist_ok=True)
    except OSError as exc:
        logger.error(f"{thread_prefix}Failed to create output dir: {exc}")
        return 0

    total_events = 0
    if external_caldav_url:
        nickname = user_email
    else:
        nickname = user.get("alias") or user_email.split("@")[0]
    # Логин внешнего сервера может содержать '\' или '/' (DOMAIN\user)
    nickname = _safe_file_component(nickname)
    timestamp = datetime.now().strftime("%y%m%d_%H%M%S")
    max_bytes = settings.output_max_mb * 1024 * 1024

    for calendar in event_calendars:
        is_default = default_calendar and calendar["url"] == default_calendar["url"]

        logger.info(f"{thread_prefix}Exporting from calendar '{calendar['name']}' for {user_email}")
        hrefs, session = caldav_calendar_query(
            calendar["url"], session, start, end,
            settings=refresh_settings, user_email=user_email,
        )
        if not hrefs:
            logger.info(f"{thread_prefix}No events found in '{calendar['name']}' for {user_email}")
            continue

        events_data: list[str] = []
        vtimezones: list[str] = []
        batch_size = 50
        for i in range(0, len(hrefs), batch_size):
            chunk = hrefs[i : i + batch_size]
            data_list = caldav_calendar_multiget(
                calendar["url"], session, [item["href"] for item in chunk]
            )
            for item in data_list:
                vcards = item.get("data", "")
                vtimezones.extend(_extract_vtimezone_blocks(vcards))
                events_data.extend(_extract_vevent_blocks(vcards))
            time.sleep(SLEEP_TIME_BETWEEN_API_CALLS)

        events_data = filter_events_by_query(events_data, query_filter)
        if not events_data:
            logger.info(f"{thread_prefix}No events match query in '{calendar['name']}' for {user_email}")
            continue

        unique_tz = list(dict.fromkeys(vtimezones))

        layer_name = _layer_file_name(calendar["name"])
        if is_default:
            layer_name = f"{{{layer_name}}}"
        base_name = f"{nickname}~{layer_name}"

        # Повторяющееся событие (мастер + исключения с RECURRENCE-ID) всегда пишется
        # в один файл: раньше разбиение по размеру могло разнести их по разным файлам,
        # и при импорте исключение уходило отдельным PUT (конфликт UID / потеря мастера).
        groups = list(_group_events_by_uid(events_data).values())
        tz_bytes = sum(len(tz.encode("utf-8")) + 1 for tz in unique_tz)

        files_created = 0
        current_groups: list[list[str]] = []
        current_size = tz_bytes
        for group in groups:
            group_size = sum(len(ev.encode("utf-8")) + 1 for ev in group)
            if current_groups and current_size + group_size > max_bytes:
                files_created += 1
                file_name = f"{base_name}~{timestamp}_{files_created}.ics"
                _write_ics_file(os.path.join(settings.output_dir, file_name), current_groups, unique_tz)
                current_groups = []
                current_size = tz_bytes
            current_groups.append(group)
            current_size += group_size

        if current_groups:
            files_created += 1
            if files_created == 1:
                file_name = f"{base_name}~{timestamp}.ics"
            else:
                file_name = f"{base_name}~{timestamp}_{files_created}.ics"
            _write_ics_file(os.path.join(settings.output_dir, file_name), current_groups, unique_tz)

        logger.info(f"{thread_prefix}Exported {len(events_data)} events into {files_created} files from '{calendar['name']}' for {user_email}")
        total_events += len(events_data)

    return total_events


def delete_events_for_user(
    settings: "SettingParams",
    user: dict,
    start: Optional[datetime],
    end: Optional[datetime],
    report_writer: csv.writer,
    report_lock: threading.Lock,
    thread_id: int = 0,
) -> int:
    thread_prefix = build_thread_prefix(thread_id)
    user_email = user.get("email")
    if not user_email:
        logger.warning(f"{thread_prefix}Пропуск пользователя без email.")
        return 0

    token = get_service_app_token(settings, user_email)
    session = build_caldav_session(user_email, token)
    try:

        calendar_home = discover_calendar_home(user_email, session)
        if not calendar_home:
            logger.error(f"{thread_prefix}Не найден calendar home для {user_email}")
            return 0

        calendars = discover_calendars(calendar_home, session)
        default_calendar = pick_default_personal_calendar(calendars)
        if not default_calendar:
            logger.warning(f"{thread_prefix}Не найден календарь по умолчанию для {user_email}")
            return 0

        logger.info(f"{thread_prefix}Удаление событий из календаря '{default_calendar['name']}' для {user_email}")

        hrefs, session = caldav_calendar_query(
            default_calendar["url"], session, start, end,
            settings=settings, user_email=user_email,
        )
        if not hrefs:
            logger.info(f"{thread_prefix}Нет событий для удаления в '{default_calendar['name']}' для {user_email}")
            with report_lock:
                report_writer.writerow([user_email, "", "", "", "", "no events found, skip"])
            return 0

        deleted_count = 0
        batch_size = 50
        for i in range(0, len(hrefs), batch_size):
            chunk = hrefs[i : i + batch_size]
            data_list = caldav_calendar_multiget(
                default_calendar["url"], session, [item["href"] for item in chunk]
            )

            href_data_map = {}
            for item in data_list:
                href_data_map[item["href"]] = item

            for href_item in chunk:
                href = href_item["href"]
                etag = href_item.get("etag")

                event_data = href_data_map.get(href, {})
                raw_data = event_data.get("data", "")
                vevent_blocks = _extract_vevent_blocks(raw_data)

                event_uid = ""
                summary = ""
                start_date = ""
                end_date = ""

                if vevent_blocks:
                    first_vevent = vevent_blocks[0]
                    event_uid = _extract_uid_from_event(first_vevent) or ""
                    summary = _extract_summary(first_vevent)
                    dtstart = _extract_dtstart(first_vevent)
                    dtend = _extract_dtend(first_vevent)
                    start_date = dtstart.strftime("%Y-%m-%d %H:%M:%S") if dtstart else ""
                    end_date = dtend.strftime("%Y-%m-%d %H:%M:%S") if dtend else ""

                success, session = caldav_delete_event(
                    session, default_calendar["url"], href,
                    etag=etag, settings=settings, user_email=user_email,
                )

                status = "ok" if success else "error"
                if success:
                    deleted_count += 1

                with report_lock:
                    report_writer.writerow([user_email, event_uid, summary, start_date, end_date, status])

                logger.debug(f"{thread_prefix}Удаление события {event_uid} ({summary}): {status}")

            time.sleep(SLEEP_TIME_BETWEEN_API_CALLS)

        logger.info(f"{thread_prefix}Удалено {deleted_count} из {len(hrefs)} событий для {user_email}")
        return deleted_count
    finally:
        session.close()

def is_user_organizer(user: dict, organizer_email: str, unique_aliases: set[str], domain_names: set[str]) -> str:
    # Проверяем, кто является организатором события: пользователь из 360 или внешний организатор
    # Если организатор - пользователь, в календарь которого импортируется событие, то возвращаем "organizer"
    # Если организатор - пользователь из 360, то возвращаем "y360_organizer"
    # Если организатор - внешний организатор, то возвращаем "external_organizer"
    

    # Событие без ORGANIZER (личная встреча без участников) принадлежит владельцу
    # календаря — раньше такие события считались «чужими» и пропускались.
    if not organizer_email:
        return "organizer"

    user_aliases = {alias.lower() for alias in user.get("aliases", [])}
    user_aliases.add(user.get("nickname", "").lower())
    organizer_email = organizer_email.lower()
    domain_part = organizer_email.rsplit("@", 1)[-1] if "@" in organizer_email else ""
    alias_part = organizer_email.rsplit("@", 1)[0] if "@" in organizer_email else ""
    if (alias_part and alias_part in user_aliases) and (domain_part and domain_part in domain_names):
        return "organizer"
    if (alias_part and alias_part in unique_aliases) and (domain_part and domain_part in domain_names):
        return "y360_organizer"
    else:
        return "external_organizer"

    
def import_events_for_user(
    settings: "SettingParams",
    nickname: str,
    import_data: dict[str, list[str]],
    start: Optional[datetime],
    end: Optional[datetime],
    conflict_policy: str,
    modify_rules: list[tuple[str, str, str, str]],
    report_writer: csv.writer,
    report_lock: threading.Lock,
    thread_id: int = 0,
    rule_apply_writer: Optional[csv.writer] = None,
    rule_apply_lock: Optional[threading.Lock] = None,
    change_organizer_policy: str = "skip",
) -> int:

    thread_prefix = build_thread_prefix(thread_id)
    users_data = get_all_api360_users(settings)
    nickname_lower = nickname.lower()
    user = next(
        (user for user in users_data if (user.get("nickname") or "").lower() == nickname_lower),
        None,
    )
    if not user:
        logger.warning(f"{thread_prefix}User '{nickname}' not found.")
        return 0
    user_email = user.get("email")
    if not user_email:
        logger.warning(f"{thread_prefix}Skipping user without email.")
        return 0
    token = get_service_app_token(settings, user_email)
    session = build_caldav_session(user_email, token)
    try:

        calendar_home = discover_calendar_home(user_email, session)
        if not calendar_home:
            logger.error(f"{thread_prefix}No calendar home for {user_email}")
            return 0

        calendars = discover_calendars(calendar_home, session)
        if not calendars:
            logger.warning(f"{thread_prefix}No calendars found for {user_email}")
            return 0

        default_calendar = pick_default_personal_calendar(calendars)

        # Build set of all possible user email addresses
        domains_data = get_all_api360_domains(settings)
        domain_names = {d["name"].lower() for d in domains_data if d.get("name")}
        nickname = user.get("nickname", "")
        unique_aliases = get_all_users_unique_aliases(settings)

        total_imported = 0
        for layer_name, files in import_data.items():
            # Determine target calendar for this layer
            if layer_name == "DEFAULT":
                calendar = default_calendar
                if not calendar:
                    logger.warning(f"{thread_prefix}No default calendar found for {user_email}, skipping layer 'DEFAULT'")
                    for file_path in files:
                        with report_lock:
                            report_writer.writerow([user_email, "DEFAULT", file_path, "", "", "skip", "default calendar not found"])
                    continue
            else:
                # Find calendar by displayname
                calendar = None
                for cal in calendars:
                    cal_name = cal.get("name")
                    if (
                        cal_name == layer_name
                        or cal_name == layer_name.replace("_", " ")
                        or _layer_file_name(cal_name or "") == layer_name
                    ):
                        calendar = cal
                        break
                if not calendar:
                    logger.warning(
                        f"{thread_prefix}Calendar layer '{layer_name}' not found "
                        f"for {user_email}, importing into default calendar"
                    )
                    calendar = default_calendar
                    if not calendar:
                        logger.warning(
                            f"{thread_prefix}No default calendar found for "
                            f"{user_email}, skipping layer '{layer_name}'"
                        )
                        for file_path in files:
                            with report_lock:
                                report_writer.writerow([
                                    user_email, layer_name, file_path,
                                    "", "", "skip",
                                    f"layer '{layer_name}' not found, "
                                    f"default calendar not found",
                                ])
                        continue

            logger.info(f"{thread_prefix}Importing into layer '{layer_name}' (calendar '{calendar['name']}') for {user_email}")

            # Читаем все файлы слоя и группируем события по UID через все файлы:
            # раньше группировка шла внутри одного файла, и мастер с исключениями,
            # оказавшиеся в разных файлах, импортировались отдельными PUT-запросами.
            layer_events: list[tuple[str, str]] = []
            layer_vtimezones: list[str] = []
            for file_path in files:
                try:
                    with open(file_path, encoding="utf-8-sig") as f:
                        ics_text = f.read()
                except (OSError, UnicodeDecodeError) as exc:
                    logger.error(f"{thread_prefix}Failed to read {file_path}: {exc}")
                    with report_lock:
                        report_writer.writerow([user_email, layer_name, file_path, "", "", "error", str(exc)])
                    continue

                ics_text = html.unescape(ics_text)
                layer_vtimezones.extend(_extract_vtimezone_blocks(ics_text))
                layer_events.extend((file_path, ev) for ev in _extract_vevent_blocks(ics_text))

            vtimezones = list(dict.fromkeys(layer_vtimezones))
            event_groups, group_files, duplicates = _group_layer_events(layer_events)
            if duplicates:
                logger.warning(
                    f"{thread_prefix}Layer '{layer_name}' for {user_email}: skipped {duplicates} duplicate VEVENT(s) "
                    f"(same UID and RECURRENCE-ID)"
                )
            # Группируем VEVENT-блоки по UID: мастер + исключения (RECURRENCE-ID)
            # идут в одном PUT-запросе, чтобы Яндекс корректно создал
            # повторяющееся событие со всеми смещениями.
            event_groups = _filter_event_groups_by_date(event_groups, start, end)

            for group_uid, event_group in event_groups.items():
                file_path = group_files[group_uid]
                master_ev = event_group[0]
                uid = _extract_uid_from_event(master_ev)
                if not uid:
                    with report_lock:
                        report_writer.writerow([user_email, layer_name, file_path, "", "", "skip", "missing UID"])
                    continue
                original_uid = uid
                is_recurring_group = len(event_group) > 1 or _event_has_rrule(master_ev)
                if is_recurring_group:
                    exceptions_count = sum(1 for e in event_group if _has_recurrence_id(e))
                    logger.debug(
                        f"{thread_prefix}Recurring event UID={uid}: "
                        f"master + {exceptions_count} exception(s)"
                    )

                # Проверка организатора — по мастер-событию
                organizer_email = _extract_organizer_email(master_ev)
                organizer_result = is_user_organizer(user, organizer_email, unique_aliases, domain_names)
                if organizer_result not in ["organizer"]:
                    if change_organizer_policy == "skip":
                        with report_lock:
                            report_writer.writerow([user_email, layer_name, file_path, uid, "", "skip", "not an organizer"])
                        logger.debug(f"{thread_prefix}Skipping event {uid}: organizer '{organizer_email}' does not match user (not an organizer)")
                        continue
                    elif change_organizer_policy == "replace":
                        original_organizer_cn = _extract_organizer_cn(master_ev)
                        # Заменяем организатора во всех VEVENT группы
                        replaced_group = []
                        for ev in event_group:
                            ev = _replace_organizer_in_event(ev, user_email)
                            if organizer_email:
                                ev = _add_attendee_accepted_to_event(ev, organizer_email, original_organizer_cn)
                            replaced_group.append(ev)
                        event_group = replaced_group
                        logger.debug(f"{thread_prefix}Event {uid}: organizer changed from '{organizer_email}' to '{user_email}' (replace)")

                action = "create"
                target_href = _event_href_name(uid)
                etag = None
                conflict = caldav_find_event_by_uid(calendar["url"], session, uid)
                if conflict:
                    if conflict_policy == "skip":
                        with report_lock:
                            report_writer.writerow([user_email, layer_name, file_path, original_uid, "", "skip", "UID conflict"])
                        continue
                    if conflict_policy == "replace":
                        action = "replace"
                        target_href = conflict["href"]
                        etag = conflict.get("etag")
                    elif conflict_policy == "regen":
                        new_uid = str(uuid.uuid4())
                        # Заменяем UID во всех VEVENT группы
                        event_group = [_replace_uid_in_event(ev, new_uid) for ev in event_group]
                        uid = new_uid
                        target_href = _event_href_name(uid)
                        action = "create"

                # Применяем правила модификации к каждому VEVENT в группе
                modified_group = []
                for ev in event_group:
                    ev, rule_changes = modify_ics_content(ev, modify_rules)
                    if rule_changes and rule_apply_writer and rule_apply_lock:
                        file_basename = os.path.basename(file_path)
                        with rule_apply_lock:
                            for rule_text, old_val, new_val in rule_changes:
                                rule_apply_writer.writerow([file_basename, rule_text, old_val, new_val])
                    modified_group.append(ev)

                # Собираем VCALENDAR: все VEVENT группы в одном запросе.
                # Нормализуем Windows-style TZID → IANA и фильтруем
                # лишние VTIMEZONE-блоки (только используемые).
                norm_group, norm_tz = _normalize_event_group_tzids(
                    modified_group, vtimezones
                )
                vcalendar = build_vcalendar(norm_group, norm_tz)
                if action == "create":
                    ok, session = caldav_put_event(
                        session,
                        calendar["url"],
                        target_href,
                        vcalendar,
                        create_only=True,
                        dry_run=settings.dry_run,
                        settings=settings,
                        user_email=user_email,
                    )
                    if ok and not settings.dry_run:
                        # Verify event was actually saved (backend accepts
                        # the request but saves asynchronously)
                        found = caldav_find_event_by_uid(calendar["url"], session, uid)
                        if not found and conflict_policy != "regen":
                            for delay in (0.1, 0.3):
                                time.sleep(delay)
                                found = caldav_find_event_by_uid(calendar["url"], session, uid)
                                if found:
                                    break
                            if not found:
                                ok = False
                                logger.error(
                                    f"{thread_prefix}Event UID={uid} not found after "
                                    f"create for {user_email}"
                                )
                        elif not found and conflict_policy == "regen":
                            regen_ok = False
                            # First regen attempt: 2 verification checks,
                            # second regen attempt: 3 verification checks
                            regen_retry_delays = [(0.1,), (0.1, 0.3)]
                            for retry_delays in regen_retry_delays:
                                new_uid = str(uuid.uuid4())
                                regen_group = [_replace_uid_in_event(ev, new_uid) for ev in modified_group]
                                uid = new_uid
                                target_href = _event_href_name(uid)
                                regen_norm, regen_tz = _normalize_event_group_tzids(
                                    regen_group, vtimezones
                                )
                                vcalendar = build_vcalendar(regen_norm, regen_tz)
                                ok, session = caldav_put_event(
                                    session,
                                    calendar["url"],
                                    target_href,
                                    vcalendar,
                                    create_only=True,
                                    dry_run=settings.dry_run,
                                    settings=settings,
                                    user_email=user_email,
                                )
                                if not ok:
                                    break
                                found = caldav_find_event_by_uid(
                                    calendar["url"], session, uid
                                )
                                if found:
                                    regen_ok = True
                                    break
                                for delay in retry_delays:
                                    time.sleep(delay)
                                    found = caldav_find_event_by_uid(
                                        calendar["url"], session, uid
                                    )
                                    if found:
                                        regen_ok = True
                                        break
                                if regen_ok:
                                    break
                            if not regen_ok:
                                ok = False
                                logger.error(
                                    f"{thread_prefix}Event creation failed after "
                                    f"UID regen attempts for {user_email}"
                                )
                else:
                    ok, session = caldav_put_event(
                        session,
                        calendar["url"],
                        target_href,
                        vcalendar,
                        etag=etag,
                        dry_run=settings.dry_run,
                        settings=settings,
                        user_email=user_email,
                    )
                if ok:
                    total_imported += 1
                    with report_lock:
                        report_writer.writerow([user_email, layer_name, file_path, original_uid, uid, action, "ok"])
                else:
                    with report_lock:
                        report_writer.writerow([user_email, layer_name, file_path, original_uid, uid, "error", "PUT failed"])
                time.sleep(SLEEP_TIME_BETWEEN_API_CALLS)

        logger.info(f"{thread_prefix}Imported {total_imported} events for {user_email}")
        return total_imported
    finally:
        session.close()


def _open_report(report_path: str, header: list[str]) -> tuple[csv.writer, TextIO]:
    report_dir = os.path.dirname(report_path)
    if report_dir:
        os.makedirs(report_dir, exist_ok=True)
    f = open(report_path, "w", encoding="utf-8", newline="")
    writer = csv.writer(f, delimiter=";")
    writer.writerow(header)
    return writer, f


def write_import_report_header(report_path: str) -> tuple[csv.writer, TextIO]:
    return _open_report(report_path, ["email", "layer", "file", "original_uid", "saved_uid", "action", "status"])


def write_delete_report_header(report_path: str) -> tuple[csv.writer, TextIO]:
    return _open_report(report_path, ["email", "event-id", "summary", "start_date", "end_date", "status"])


def write_rule_apply_report_header(report_path: str) -> tuple[csv.writer, TextIO]:
    return _open_report(report_path, ["file", "rule", "old", "new"])


def close_report_writer(report_file) -> None:
    if report_file:
        report_file.close()


_DATE_OFFSET_RE = re.compile(r"^[+-]\d+[dDwWmMyY]$")


def _is_valid_range_part(value: str) -> bool:
    if value == "*":
        return True
    try:
        return parse_date_input(value) is not None
    except ValueError:
        return False


def _split_date_range(value: str) -> Optional[tuple[str, str]]:
    """Делит строку диапазона по тому дефису, с обеих сторон которого стоят корректные даты.

    Раньше строка делилась по первому '-', поэтому не работали форматы
    YYYY-MM-DD (2024-01-01 - 2024-12-31) и смещения (-7d - +7d), которые
    поддерживает parse_date_input.
    """
    for idx, ch in enumerate(value):
        if ch != "-" or idx == 0:
            continue
        left, right = value[:idx], value[idx + 1:]
        if left and right and _is_valid_range_part(left) and _is_valid_range_part(right):
            return left, right
    return None


def prompt_date_range() -> tuple[bool, Optional[datetime], Optional[datetime]]:
    """
    Запрашивает у пользователя диапазон дат в формате <начало> - <конец> (включительно) (* для любой даты).
    Возвращает кортеж из успеха ввода и двух объектов datetime (None — граница не задана).
    """
    print('\nВведите диапазон дат в формате <начало> - <конец> (включительно) (* для любой даты).')
    print('Например: 01.01.2024 - 31.12.2024, * - 31.12.24, * или Enter — все даты.\n')
    while True:
        date_range_input = input('Диапазон: ').strip()
        # Удаляем пробелы вокруг и между дат и дефисом
        date_range_input = date_range_input.replace(' ', '')
        if not date_range_input or date_range_input == '*':
            return True, None, None

        parts = _split_date_range(date_range_input)
        if not parts:
            print('Ошибка: Некорректный формат. Введите две даты через дефис ("-") либо * для пропуска.')
            continue

        from_value, to_value = parts
        start = None if from_value == '*' else parse_date_input(from_value)
        end = None if to_value == '*' else parse_date_input(to_value)

        # Конечная дата включительно: без этого "31.12.2024" означало 31.12.2024 00:00,
        # и события последнего дня диапазона не попадали в выборку.
        if end is not None and not _DATE_OFFSET_RE.match(to_value):
            end = end.replace(hour=23, minute=59, second=59)

        if start is not None and end is not None and start > end:
            print('Ошибка: Начальная дата не может быть позже конечной. Попробуйте снова.')
            continue

        return True, start, end


def prompt_conflict_policy() -> str:
    print("\nЧто делать с дубликатами UID событий:")
    print("1. Пропустить импортируемые события")
    print("2. Заменить существующие события")
    print("3. Сгенерировать новый UID")
    while True:
        choice = input("Выбор (1-3) (Enter — выход в меню): ").strip()
        if not choice:
            return "exit"
        if choice in {"1", "2", "3"}:
            return {"1": "skip", "2": "replace", "3": "regen"}[choice]
        print("\nОшибка: введите 1, 2 или 3.")


def prompt_change_organizer_policy() -> str:
    print("\nСобытия, где организатор не совпадает с пользователем, куда импортируются события,")
    print("не могут быть сохранены без модификации организатора. Выберите действие:")
    print("1. Не менять организатора, событие не будет импортировано.")
    print("2. Заменить организатора на пользователя, куда импортируются события.")
    while True:
        choice = input("Выбор (1-2) (Enter — выход в меню): ").strip()
        if not choice:
            return "exit"
        if choice in {"1", "2"}:
            return {"1": "skip", "2": "replace"}[choice]
        print("\nОшибка: введите 1 или 2.")


def prompt_query_filter() -> str:
    print("\nВведите фильтр для событий (в формате: ical_TAG operator value)")
    print("Например: CLASS:Public или ORGANIZER contains john.doe@example.com\n")
    return input("Фильтр (Enter - без фильтра): ").strip()


def _split_active_users(users: list[dict]) -> tuple[list[dict], list[dict]]:
    """Делит пользователей на доступных для работы с календарём и заблокированных.
    Пользователи с личной учёткой (id не с 113...) пропускаются."""
    active: list[dict] = []
    blocked: list[dict] = []
    for user in users:
        user_display = user.get("nickname") or user.get("id") or str(user)
        if not user.get("isEnabled", True):
            logger.error(f"Пользователь {user_display} заблокирован, работа с его календарём невозможна. Пропуск пользователя.")
            blocked.append(user)
        elif not str(user.get('id')).startswith('113'):
            logger.debug(f"Пользователь {user_display} имеет личную учётку, работа с его календарём невозможна.")
        else:
            active.append(user)
    return active, blocked


def _prompt_active_users(settings: "SettingParams") -> Optional[tuple[list[dict], list[dict]]]:
    """Запрашивает пользователей до тех пор, пока не останется хотя бы один доступный.
    Возвращает (доступные, заблокированные) или None для выхода в меню."""
    while True:
        users_to_add, break_flag, double_users_flag, _all_users_flag = find_users_prompt(settings)
        if break_flag or double_users_flag or not users_to_add:
            return None
        active, blocked = _split_active_users(users_to_add)
        if active:
            return active, blocked
        logger.error("После фильтрации не осталось пользователей для обработки. Попробуйте ввести пользователей заново.")


def _wait_futures(futures: dict) -> None:
    """Дожидается задач пула. Ошибка одного пользователя (например, TokenError) больше
    не прерывает всю операцию и не завершает скрипт — она логируется, остальные продолжают."""
    for future, label in futures.items():
        try:
            future.result()
        except Exception as exc:
            logger.error(f"Ошибка при обработке {label}: {type(exc).__name__}: {exc}")
            logger.debug(traceback.format_exc())


def export_menu_parallel(settings: "SettingParams"):
    selected = _prompt_active_users(settings)
    if selected is None:
        return
    users_to_add, _blocked = selected

    result, start, end = prompt_date_range()
    if not result:
        return
    query_filter = prompt_query_filter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=settings.threads) as executor:
        futures = {
            executor.submit(export_events_for_user, settings, user, start, end, query_filter, idx):
                user.get("email") or user.get("nickname")
            for idx, user in enumerate(users_to_add, start=1)
        }
        _wait_futures(futures)


def export_from_external_caldav_server(settings: "SettingParams"):

    if not settings.external_caldav_url:
        logger.error("External CalDAV URL is not set. Please set the EXTERNAL_CALDAV_URL environment variable.")
        return

    while True:
        users_to_add, break_flag = get_external_caldav_users_prompt(settings)
        if break_flag:
            return
        if users_to_add:
            break

    logger.info(f"Будут экспортированы события из календаря по умолчанию для {len(users_to_add)} пользователей.")
    result, start, end = prompt_date_range()
    if not result:
        return
    query_filter = prompt_query_filter()
    with concurrent.futures.ThreadPoolExecutor(max_workers=settings.threads) as executor:
        futures = {
            executor.submit(
                export_events_for_user,
                settings, user, start, end, query_filter, idx, settings.external_caldav_url,
            ): user.get("login")
            for idx, user in enumerate(users_to_add, start=1)
        }
        _wait_futures(futures)


def delete_menu_parallel(settings: "SettingParams"):
    selected = _prompt_active_users(settings)
    if selected is None:
        return
    users_to_add, blocked_users = selected

    result, start, end = prompt_date_range()
    if not result:
        return

    user_emails = [u.get("email", u.get("nickname", "?")) for u in users_to_add]
    print(f"\nБудут удалены события из календаря по умолчанию для {len(users_to_add)} пользователей:")
    if len(user_emails) > 5:
        print(f"  Всего будет обработано {len(user_emails)} календарей пользователей.")
    else:
        for email in user_emails:
            print(f"  - {email}")
    date_info = ""
    if start:
        date_info += f" с {start.strftime('%d.%m.%Y')}"
    if end:
        date_info += f" по {end.strftime('%d.%m.%Y')}"
    if not start and not end:
        date_info = " за все даты"
    print(f"Диапазон дат:{date_info}")
    if settings.create_cancel_rules_for_events_deletions:
        print("\nВ глобальных настройках установлена опция автоматического создания транспортного правила")
        print("для блокировки уведомлений об удалении событий (если такого правила ещё нет).")
        print("Если вы хотите отключить эту опцию, установите параметр CREATE_CANCEL_RULES_FOR_EVENTS_DELETIONS=false в .env.")
    else:
        print("\nВ глобальных настройках выключена опция автоматического создания транспортного правила")
        print("для блокировки уведомлений об удалении событий (если такого правила ещё нет).")
        print("!!! ВСЕМ УЧАСТНИКАМ УДАЛЯЕМЫХ СОБЫТИЙ БУДЕТ ОТПРАВЛЕНО УВЕДОМЛЕНИЕ ОБ УДАЛЕНИИ.")
        print("Если вы хотите отключить такие уведомления, установите параметр CREATE_CANCEL_RULES_FOR_EVENTS_DELETIONS=true в .env.")
    confirm = input("\nПодтвердите удаление (yes/да): ").strip().lower()
    if confirm not in ("yes", "да", "y"):
        print("Удаление отменено.")
        return

    if settings.create_cancel_rules_for_events_deletions:
        add_mail_routing_rule(settings)
    report_name = f"delete_{datetime.now().strftime('%y%m%d_%H%M%S')}.csv"
    report_path = os.path.join(settings.reports_dir, report_name)
    writer, report_file = write_delete_report_header(report_path)
    report_lock = threading.Lock()
    try:
        # Записываем заблокированных пользователей в отчёт
        for user in blocked_users:
            user_email = user.get("email", user.get("nickname", "?"))
            writer.writerow([user_email, "", "", "", "", "user blocked, skip"])

        with concurrent.futures.ThreadPoolExecutor(max_workers=settings.threads) as executor:
            futures = {
                executor.submit(
                    delete_events_for_user, settings, user, start, end, writer, report_lock, idx,
                ): user.get("email")
                for idx, user in enumerate(users_to_add, start=1)
            }
            _wait_futures(futures)
    finally:
        close_report_writer(report_file)
    logger.info(f"Отчёт об удалении сохранён в {report_path}")


def _user_aliases(user: dict) -> list[str]:
    aliases = user.get("aliases", [])
    if isinstance(aliases, str):
        return [a.strip().lower() for a in aliases.split(",") if a.strip()]
    if isinstance(aliases, list):
        return [a.strip().lower() for a in aliases if isinstance(a, str) and a.strip()]
    return []


def _user_matches_key(user: dict, key: str) -> bool:
    nickname = (user.get("nickname") or "").strip().lower()
    key_lower = key.strip().lower()
    return bool(nickname) and (key_lower == nickname or key_lower in _user_aliases(user))


def _build_user_files_map(
    users: list[dict], files_map: dict[str, dict[str, list[str]]]
) -> dict[str, dict[str, list[str]]]:
    """Для каждого пользователя собирает его файлы по nickname и aliases,
    нормализуя ключ к nickname. Дубликаты имён файлов в слое отбрасываются."""
    filtered_files_map: dict[str, dict[str, list[str]]] = {}
    for user in users:
        nickname = (user.get("nickname") or "").strip().lower()
        if not nickname:
            continue
        for key, layers in files_map.items():
            if not _user_matches_key(user, key):
                continue
            existing = filtered_files_map.setdefault(nickname, {})
            for layer_name, layer_files in layers.items():
                existing.setdefault(layer_name, []).extend(layer_files)
            if key.strip().lower() != nickname:
                logger.debug(f"Файлы из '{key}' перенесены в ключ '{nickname}' (алиас -> nickname)")

    for nickname, user_layers in filtered_files_map.items():
        for layer_name, files in user_layers.items():
            seen_files = set()
            unique_files = []
            duplicate_files = []
            for fname in files:
                base_fname = os.path.basename(fname)
                if base_fname in seen_files:
                    duplicate_files.append(base_fname)
                else:
                    seen_files.add(base_fname)
                    unique_files.append(fname)
            if duplicate_files:
                logger.warning(
                    f"Обнаружены дубликаты файлов для пользователя '{nickname}', слой '{layer_name}': "
                    f"{', '.join(duplicate_files)}. Дубликаты удалены."
                )
                user_layers[layer_name] = unique_files
    return filtered_files_map


def _run_import(
    settings: "SettingParams",
    user_files_map: dict[str, dict[str, list[str]]],
    all_files_map: dict[str, dict[str, list[str]]],
    blocked_users: list[dict],
    mapping_applied: list[tuple[str, str]],
    conflict_policy: str,
    change_organizer_policy: str,
    start: Optional[datetime],
    end: Optional[datetime],
) -> None:
    ics_modify_rules = load_modify_rules(settings)
    timestamp = datetime.now().strftime('%y%m%d_%H%M%S')
    report_path = os.path.join(settings.reports_dir, f"import_{timestamp}.csv")
    writer, report_file = write_import_report_header(report_path)
    report_lock = threading.Lock()
    rule_apply_base, rule_apply_ext = os.path.splitext(settings.rule_apply_report)
    rule_apply_path = os.path.join(settings.reports_dir, f"{rule_apply_base}_{timestamp}{rule_apply_ext}")
    rule_apply_writer, rule_apply_file = write_rule_apply_report_header(rule_apply_path)
    rule_apply_lock = threading.Lock()
    try:
        # Файлы заблокированных пользователей — в отчёт (колонки как в заголовке отчёта;
        # раньше строка писалась со сдвигом: файл в колонке layer, статус в saved_uid).
        for user in blocked_users:
            nickname = (user.get("nickname") or "").strip().lower()
            if not nickname:
                continue
            for key, layers in all_files_map.items():
                if not _user_matches_key(user, key):
                    continue
                for layer_name, layer_files in layers.items():
                    for fname in layer_files:
                        writer.writerow([nickname, layer_name, fname, "", "", "skip", "user blocked"])

        with concurrent.futures.ThreadPoolExecutor(max_workers=settings.threads) as executor:
            futures = {
                executor.submit(
                    import_events_for_user,
                    settings,
                    nickname,
                    data,
                    start,
                    end,
                    conflict_policy,
                    ics_modify_rules,
                    writer,
                    report_lock,
                    idx,
                    rule_apply_writer=rule_apply_writer,
                    rule_apply_lock=rule_apply_lock,
                    change_organizer_policy=change_organizer_policy,
                ): nickname
                for idx, (nickname, data) in enumerate(user_files_map.items(), start=1)
            }
            _wait_futures(futures)
    finally:
        close_report_writer(report_file)
        close_report_writer(rule_apply_file)
    logger.info(f"Import report saved to {report_path}")
    logger.info(f"Rule apply report saved to {rule_apply_path}")
    if mapping_applied:
        logger.info(f"User mapping: при импорте были применены следующие замены алиасов ({len(mapping_applied)}):")
        for ext_a, y360_a in mapping_applied:
            logger.info(f"  '{ext_a}' -> '{y360_a}'")
    else:
        logger.info("User mapping: замены алиасов не применялись.")


def _log_files_map_totals(user_files_map: dict[str, dict[str, list[str]]]) -> None:
    total_files = sum(
        len(file_list)
        for user_layers in user_files_map.values()
        for file_list in user_layers.values()
    )
    logger.info(f"Для обработки выбрано пользователей: {len(user_files_map)}, всего файлов: {total_files}")


def _load_input_files_map(settings: "SettingParams"):
    files_map = parse_input_files(settings.input_dir)
    if not files_map:
        logger.error(f"No input .ics files found in {settings.input_dir}")
        return None, []
    user_mapping = load_user_mapping(settings.user_mapping_file)
    return apply_user_mapping(files_map, user_mapping)


def import_menu_parallel(settings: "SettingParams"):
    files_map, mapping_applied = _load_input_files_map(settings)
    if not files_map:
        return

    selected = _prompt_active_users(settings)
    if selected is None:
        return
    users_to_add, blocked_users = selected

    user_files_map = _build_user_files_map(users_to_add, files_map)
    _log_files_map_totals(user_files_map)
    if not user_files_map:
        logger.error(f"В каталоге {settings.input_dir} нет файлов для выбранных пользователей.")
        return

    conflict_policy = prompt_conflict_policy()
    if conflict_policy == "exit":
        return
    change_organizer_policy = prompt_change_organizer_policy()
    if change_organizer_policy == "exit":
        return
    result, start, end = prompt_date_range()
    if not result:
        return

    _run_import(
        settings, user_files_map, files_map, blocked_users, mapping_applied,
        conflict_policy, change_organizer_policy, start, end,
    )


def import_menu_parallel_without_params(settings: "SettingParams"):
    print(f"\nИмпорт событий из ics файлов в каталоге {settings.input_dir}.")
    print("Будут импортированы все события из ics файлов в каталоге для всех пользователей организации.")
    print("В случае дубликатов UID событий будут генерированы новые UID.")
    print("События, где пользователь не является организатором, будут пропущены.")
    print(f"К событиям будут применены правила модификации из файла {settings.modify_rules}.")
    answer = input("Подтвердите импорт (yes/да): ").strip().lower()
    if answer not in ("yes", "да", "y"):
        print("Импорт отменен.")
        return

    files_map, mapping_applied = _load_input_files_map(settings)
    if not files_map:
        return

    users_to_add, blocked_users = _split_active_users(get_all_api360_users(settings))
    if not users_to_add:
        logger.error("После фильтрации не осталось пользователей для обработки.")
        return

    user_files_map = _build_user_files_map(users_to_add, files_map)
    _log_files_map_totals(user_files_map)
    if not user_files_map:
        logger.error(f"В каталоге {settings.input_dir} нет файлов для пользователей организации.")
        return

    _run_import(
        settings, user_files_map, files_map, blocked_users, mapping_applied,
        conflict_policy="regen", change_organizer_policy="skip", start=None, end=None,
    )


def list_calendars_for_user(settings: "SettingParams"):
    selected = _prompt_active_users(settings)
    if selected is None:
        return
    users_to_add, _blocked = selected

    for user in users_to_add:
        user_email = user.get("email")
        if not user_email:
            continue
        try:
            token = get_service_app_token(settings, user_email)
        except TokenError as exc:
            logger.error(f"Не удалось получить токен для {user_email}: {exc}")
            continue
        with build_caldav_session(user_email, token) as session:
            calendar_home = discover_calendar_home(user_email, session)
            if not calendar_home:
                logger.error(f"No calendar home for {user_email}")
                continue
            calendars = discover_calendars(calendar_home, session)
        default_calendar = pick_default_personal_calendar(calendars)
        logger.info(f"Calendars for {user_email}:")
        for cal in calendars:
            cal_name = cal['name']
            if default_calendar and cal["url"] == default_calendar["url"]:
                cal_name += " (по умолчанию)"
            logger.info(f" - {cal_name} ({cal['url']})")


def check_token_permissions_simple(token: str, org_id: int, needed_permissions: list) -> tuple[bool, bool]:
            
     result, data = check_token_permissions_api(token)
     if not result:
        return True, False
     else:
        try:
            # Извлечение scopes и orgIds из ответа
            token_scopes = data.get('scopes', [])
            token_org_ids = data.get('orgIds', [])
            login = data.get('login', 'unknown')
            
            logger.info(f"Проверка прав доступа для токена пользователя: {login}")
            logger.debug(f"Доступные права: {token_scopes}")
            logger.debug(f"Доступные организации: {token_org_ids}")
            
            # Проверка наличия org_id в списке доступных организаций
            if str(org_id) not in [str(org) for org in token_org_ids]:
                logger.error("=" * 100)
                logger.error(f"ОШИБКА: Токен не имеет доступа к организации с ID {org_id}")
                logger.error(f"Доступные организации для этого токена: {token_org_ids}")
                logger.error("=" * 100)
                return True, False

            # Проверка наличия всех необходимых прав
            missing_permissions = []
            for permission in needed_permissions:
                if permission not in token_scopes:
                    missing_permissions.append(permission)
            
            if missing_permissions:
                logger.error("=" * 100)
                logger.error("ОШИБКА: У токена отсутствуют необходимые права доступа!")
                logger.error("Недостающие права:")
                for perm in missing_permissions:
                    logger.error(f"  - {perm}")
                logger.error("=" * 100)
                return False, False

            logger.info("✓ Все необходимые права доступа присутствуют")
            logger.info(f"✓ Доступ к организации {org_id} подтвержден")
            return False, True
        except json.JSONDecodeError as e:
            logger.error(f"Ошибка при парсинге ответа от API: {e}")
            return False, result
        except Exception as e:
            logger.error(f"Неожиданная ошибка при проверке прав доступа: {type(e).__name__}: {e}")
            return False, result

def check_token_permissions_for_service_application(settings: "SettingParams") -> bool:
    needed_permissions = ["ya360_security:service_applications_read",
                          "ya360_security:service_applications_write",]

    # Раньше функция вызывалась с тремя аргументами при сигнатуре из одного -> TypeError
    result, data = check_token_permissions_api(settings.oauth_token)
    if not result:
        return False
    else:
        try:
            token_scopes = data.get('scopes', [])
            token_org_ids = data.get('orgIds', [])
            login = data.get('login', 'unknown')
            if "@" in login:
                logger.error("ОШИБКА: Токен выписан НЕ личной учётке Яндекс. Невозможно настроить сервисное приложение.")
                return False

            logger.info(f"Проверка прав доступа для токена пользователя: {login}")
            logger.debug(f"Доступные права: {token_scopes}")
            logger.debug(f"Доступные организации: {token_org_ids}")

            for permission in needed_permissions:
                if permission not in token_scopes:
                    logger.error(f"ОШИБКА: Токен не имеет права {permission}. Невозможно настроить сервисное приложение.")
                    return False

            logger.info("✓ Все необходимые права доступа для создания сервисного приложения присутствуют.")
            logger.info(f"✓ Доступ к организации {settings.org_id} подтвержден")
            return True
        except Exception as e:
            logger.error(f"Неожиданная ошибка при проверке прав доступа: {type(e).__name__}: {e}")
            return False

def check_token_permissions_api(token: str) -> tuple[bool, dict]:
    """
    Проверяет права доступа для заданного токена.
    
    Args:
        token: OAuth токен для проверки
        
    Returns:
        bool: Статус выполнения запроса
        dict: Данные ответа от API
    """
    url = 'https://api360.yandex.net/whoami'
    headers = {
        'Authorization': f'OAuth {token}'
    }
    result = None
    try:
        response = requests.get(url, headers=headers)

        # Проверка валидности токена
        if response.status_code != HTTPStatus.OK:
            logger.error(f"Невалидный токен. Статус код: {response.status_code}")
            if response.status_code == 401:
                logger.error("Токен недействителен или истек срок его действия.")
            else:
                logger.error(f"Ошибка при проверке токена: {response.text}")
            return False, result
        
        data = response.json()
        return True, data
        
    except requests.exceptions.RequestException as e:
        logger.error(f"Ошибка при выполнении запроса к API: {e}")
        return False, result
    except json.JSONDecodeError as e:
        logger.error(f"Ошибка при парсинге ответа от API: {e}")
        return False, result
    except Exception as e:
        logger.error(f"Неожиданная ошибка при проверке прав доступа: {type(e).__name__}: {e}")
        return False, result

def activate_service_applications(settings: "SettingParams") -> bool:
    """
    Активирует работу сервисных приложений.
    Спецификация API: https://yandex.ru/dev/api360/doc/ru/ref/ServiceApplicationsService/ServiceApplicationsService_Activate
    
    Args:
        settings: Объект настроек с oauth_token и org_id
        
    Returns:
        bool: True если функция активирована, False в случае ошибки
    """
    url = f"{DEFAULT_360_API_URL}/security/v1/org/{settings.org_id}/service_applications/activate"
    headers = {"Authorization": f"OAuth {settings.oauth_token}"}
    retries = 0
    try:
        while True:
            logger.debug(f"POST URL - {url}")
            response = requests.post(url, headers=headers)
            logger.debug(f'X-Request-Id: {response.headers.get("X-Request-Id","")}')
            if response.status_code != HTTPStatus.OK.value:
                logger.error(f"Ошибка при активации сервисных приложений: {response.status_code}. Сообщение: {response.text}")
                if retries < MAX_RETRIES:
                    logger.error(f"Повторная попытка ({retries+1}/{MAX_RETRIES})")
                    time.sleep(RETRIES_DELAY_SEC * (retries + 1))
                    retries += 1
                else:
                    logger.error("Превышено максимальное количество попыток.")
                    return False
            else:
                logger.info("Сервисные приложения активированы.")
                return True
    except requests.exceptions.RequestException as e:
        logger.error(f"Ошибка при выполнении запроса к API: {e}")
        return False
    except Exception as e:
        logger.error(f"Неожиданная ошибка при активации сервисных приложений: {type(e).__name__}: {e}")
        return False

def _api_error_message(response: requests.Response) -> str:
    """Поле message из JSON-ответа API с ошибкой ('' если тела нет или это не JSON)."""
    try:
        payload = response.json()
    except ValueError:
        return ""
    return payload.get("message", "") if isinstance(payload, dict) else ""


def get_service_applications(settings: "SettingParams") -> tuple[Optional[list], Optional[str]]:
    """
    Получает список сервисных приложений организации.
    Спецификация API: https://yandex.ru/dev/api360/doc/ru/ref/ServiceApplicationsService/ServiceApplicationsService_Get
    
    Args:
        settings: Объект настроек с oauth_token и org_id
        
    Returns:
        list: Список сервисных приложений, None в случае ошибки
    """
    url = f"{DEFAULT_360_API_URL}/security/v1/org/{settings.org_id}/service_applications"
    headers = {"Authorization": f"OAuth {settings.oauth_token}"}
    retries = 0
    try:
        while True:
            logger.debug(f"GET URL - {url}")
            response = requests.get(url, headers=headers)
            logger.debug(f'X-Request-Id: {response.headers.get("X-Request-Id","")}')
            if response.status_code != HTTPStatus.OK.value:
                message = _api_error_message(response)
                if message == 'feature is not active':
                    logger.error('Функционал сервисных приложений не активирован в организации.')
                    return None, message
                if message == 'Not an owner':
                    logger.error('Токен в параметре OAUTH_TOKEN_ARG выписан НЕ ВЛАДЕЛЬЦЕМ организации (с учеткой в @yandex.ru).')
                    logger.error('Невозможно настроить сервисное приложение. Получите правильный токен и повторите попытку.')
                    return None, message
                logger.error(f"Ошибка при получении списка сервисных приложений: {response.status_code}. Сообщение: {response.text}")
                if retries < MAX_RETRIES:
                    retries += 1
                    logger.error(f"Повторная попытка ({retries}/{MAX_RETRIES})")
                    time.sleep(RETRIES_DELAY_SEC * (retries + 1))
                else:
                    logger.error("Превышено максимальное количество попыток.")
                    return None, message or f"HTTP {response.status_code}"
            else:
                applications = response.json().get("applications", [])
                logger.info(f"Получен список {len(applications)} сервисных приложений.")
                if not check_service_app_response(settings, response):
                    logger.debug(f"Сервисное приложение {settings.service_app_id} не найдено в списке сервисных приложений организации или не имеет необходимых прав доступа.")
                    return applications, f"Сервисное приложение {settings.service_app_id} не найдено в списке сервисных приложений организации или не имеет необходимых прав доступа."
                return applications, None
    except requests.exceptions.RequestException as e:
        logger.error(f"Ошибка при выполнении запроса к API: {e}")
        return None, f'{e.__class__.__name__}: {e}'  
    except json.JSONDecodeError as e:
        logger.error(f"Ошибка при парсинге ответа от API: {e}")
        return None, f'{e.__class__.__name__}: {e}'  
    except Exception as e:
        logger.error(f"Неожиданная ошибка при получении сервисных приложений: {type(e).__name__}: {e}")
        return None, f'{e.__class__.__name__}: {e}'     

def export_service_applications_api_data(settings: "SettingParams") -> bool:
    """
    Выгружает ответ API сервисных приложений в файл.
    Спецификация API: https://yandex.ru/dev/api360/doc/ru/ref/ServiceApplicationsService/ServiceApplicationsService_Get
    """
    if not settings.service_app_api_data_file:
        logger.error("SERVICE_APP_API_DATA_FILE не задан. Невозможно сохранить данные.")
        return False

    applications, error_message = get_service_applications(settings)
    if applications is None:
        logger.error("Не удалось получить данные API сервисных приложений. Проверьте настройки и повторите попытку.")
        return False
    if not applications:
        logger.error("Список сервисных приложений пуст. Невозможно выгрузить данные.")

    data = {"applications": applications}
    target_dir = os.path.dirname(settings.service_app_api_data_file)
    if target_dir and not os.path.exists(target_dir):
        os.makedirs(target_dir)
    base_name = os.path.basename(settings.service_app_api_data_file)
    name_root, ext = os.path.splitext(base_name)
    timestamp = datetime.now().strftime("%y%m%d_%H%M%S")
    output_filename = f"{name_root}_{timestamp}{ext}"
    output_path = os.path.join(target_dir, output_filename) if target_dir else output_filename
    with open(output_path, "w", encoding="utf-8") as file:
        json.dump(data, file, ensure_ascii=False, indent=2)
        logger.info(
            f"Данные API сервисных приложений сохранены в файл: {output_path} "
            f"(кол-во приложений: {len(applications)})"
        )
    return True

def import_service_applications_api_data(settings: "SettingParams") -> bool:
    """
    Загружает параметры сервисных приложений из файла и отправляет в API.
    Спецификация API: https://yandex.ru/dev/api360/doc/ru/ref/ServiceApplicationsService/ServiceApplicationsService_Create
    """
    if not settings.service_app_api_data_file:
        logger.error("SERVICE_APP_API_DATA_FILE не задан. Невозможно загрузить данные.")
        return False

    if not os.path.exists(settings.service_app_api_data_file):
        logger.error(f"Файл не найден: {settings.service_app_api_data_file}")
        return False

    try:
        with open(settings.service_app_api_data_file, "r", encoding="utf-8") as file:
            raw_content = file.read()
    except OSError as e:
        logger.error(f"Ошибка при чтении файла {settings.service_app_api_data_file}: {e}")
        return False

    if not raw_content.strip():
        logger.error(f"Файл пустой: {settings.service_app_api_data_file}")
        return False

    try:
        payload = json.loads(raw_content)
    except json.JSONDecodeError as e:
        logger.error(f"Некорректный JSON в файле {settings.service_app_api_data_file}: {e}")
        return False

    if not isinstance(payload, dict) or "applications" not in payload:
        logger.error("Некорректный формат данных: отсутствует ключ applications.")
        return False

    if not isinstance(payload["applications"], list):
        logger.error("Некорректный формат данных: applications должен быть списком.")
        return False

    CHECK_TOKEN_PERMISSIONS = ["ya360_security:service_applications_read",
                               "ya360_security:service_applications_write",]
    success, data = check_token_permissions_api(settings.oauth_token)
    if not success:
        logger.error("Не удалось проверить токен (параметр OAUTH_TOKEN_ARG). Проверьте настройки.")
        return False
    token_scopes = data.get('scopes', [])
    for permission in CHECK_TOKEN_PERMISSIONS:
        if permission not in token_scopes:
            logger.error(f"В токене OAUTH_TOKEN_ARG отсутствуют необходимые права доступа ({', '.join(CHECK_TOKEN_PERMISSIONS)}) для модификации списка сервисных приложений. Проверьте настройки и повторите попытку.")
            return False

    url = f"{DEFAULT_360_API_URL}/security/v1/org/{settings.org_id}/service_applications"
    headers = {"Authorization": f"OAuth {settings.oauth_token}"}
    retries = 0
    activated = False
    try:
        while True:
            logger.debug(f"POST URL - {url}")
            response = requests.post(url, headers=headers, json=payload)
            logger.debug(f'X-Request-Id: {response.headers.get("X-Request-Id","")}')
            if response.status_code != HTTPStatus.OK.value:
                message = _api_error_message(response)
                if message == 'feature is not active':
                    if not activated:
                        logger.error('Функционал сервисных приложений не активирован в организации. Выполняем активацию...')
                        result = activate_service_applications(settings)
                        if not result:
                            logger.error("Не удалось активировать функционал сервисных приложений. Проверьте настройки и повторите попытку.")
                            return False
                        activated = True
                        time.sleep(1)
                        continue
                    else:
                        logger.error('Функционал сервисных приложений не активирован в организации. Проверьте настройки и повторите попытку.')
                        return False
                if message == 'Not an owner':
                    logger.error('Токен в параметре OAUTH_TOKEN_ARG выписан НЕ ВЛАДЕЛЬЦЕМ организации (с учеткой в @yandex.ru).')
                    logger.error('Невозможно настроить сервисное приложение. Получите правильный токен и повторите попытку.')
                    return False
                logger.error(f"Ошибка при загрузке сервисных приложений из файла: {response.status_code}. Сообщение: {response.text}")
                if retries < MAX_RETRIES:
                    logger.error(f"Повторная попытка ({retries+1}/{MAX_RETRIES})")
                    time.sleep(RETRIES_DELAY_SEC * (retries + 1))
                    retries += 1
                else:
                    logger.error("Превышено максимальное количество попыток.")
                    return False
            else:
                app_count = len(payload.get("applications", []))
                logger.info(f"Данные сервисных приложений успешно загружены из файла (кол-во приложений: {app_count}).")
                return True
    except requests.exceptions.RequestException as e:
        logger.error(f"Ошибка при выполнении запроса к API: {e}")
        return False
    except Exception as e:
        logger.error(f"Неожиданная ошибка при загрузке сервисных приложений из файла: {type(e).__name__}: {e}")
        return False


def merge_service_app_permissions(existing_permissions: list, required_permissions: list) -> list:
    merged_permissions = list(existing_permissions) if existing_permissions else []
    existing_set = set(merged_permissions)
    for permission in required_permissions:
        if permission not in existing_set:
            merged_permissions.append(permission)
            existing_set.add(permission)
    return merged_permissions

def check_service_app_response(settings: "SettingParams", response: requests.Response) -> bool:
    """
    Проверяет ответ API сервисных приложений.
    """
    if len(response.json().get("applications", [])) == 0:
        return False
    
    found_app = False
    for app in response.json().get("applications", []):
        if app.get("id") == settings.service_app_id:
            found_app = True
            scopes = app.get("scopes", [])
            found_permissions = True
            for perm in SERVICE_APP_PERMISSIONS:
                if perm not in scopes:
                    found_permissions = False
                    break
            if not found_permissions:
                return False
    if not found_app:
        return False

    return True

def setup_service_application(settings: "SettingParams") -> bool:
    """
    Добавляет/обновляет сервисное приложение и его разрешения.
    Спецификация API: https://yandex.ru/dev/api360/doc/ru/ref/ServiceApplicationsService/ServiceApplicationsService_Create
    
    Args:
        settings: Объект настроек с oauth_token, org_id и service_app_id
        
    Returns:
        bool: True если операция успешна или не требуется, False в случае ошибки
    """
    if not settings.service_app_id:
        logger.error("Параметр SERVICE_APP_ID не задан. Невозможно настроить сервисное приложение.")
        return False

    if not settings.service_app_secret:
        logger.error("Параметр SERVICE_APP_SECRET не задан. Невозможно проверить статус сервисного приложения.")
        return False

    CHECK_TOKEN_PERMISSIONS = ["ya360_security:service_applications_read",
                               "ya360_security:service_applications_write",]
    success, data = check_token_permissions_api(settings.oauth_token)
    if not success:
        logger.error("Не удалось проверить токен (параметр OAUTH_TOKEN_ARG). Проверьте настройки.")
        return False
    token_scopes = data.get('scopes', [])
    for permission in CHECK_TOKEN_PERMISSIONS:
        if permission not in token_scopes:
            logger.error(f"В токене OAUTH_TOKEN_ARG отсутствуют необходимые права доступа ({', '.join(CHECK_TOKEN_PERMISSIONS)}) для модификации списка сервисных приложений. Проверьте настройки и повторите попытку.")
            return False
    
    applications, error_message = get_service_applications(settings)
    if applications is None:
        if error_message == 'feature is not active':
            result = activate_service_applications(settings)
            if not result:
                logger.error("Не удалось активировать функционал сервисных приложений. Проверьте настройки и повторите попытку.")
                return False
            # После активации список приложений пуст — ниже приложение будет добавлено.
            # Раньше здесь был len(None) -> TypeError, а для пустого списка настройка
            # прерывалась, поэтому первое приложение в организации создать было нельзя.
            applications = []
        else:
            return False

    client_id = settings.service_app_id
    required_permissions = SERVICE_APP_PERMISSIONS
    changed = False
    found = False

    if applications:
        for app in applications:
            if app.get("id") == client_id:
                found = True
                logger.info(f"Сервисное приложение с ID {client_id} найдено в списке сервисных приложений организации.")
                current_permissions = app.get("scopes", [])
                merged_permissions = merge_service_app_permissions(current_permissions, required_permissions)
                if merged_permissions != current_permissions:
                    app["scopes"] = merged_permissions
                    changed = True
                    logger.info("Добавлены недостающие разрешения для сервисного приложения.")
                else:
                    logger.info("Сервисное приложение уже содержит все необходимые разрешения. Выполняем проверку валидности токена сервисного приложения...")
                    return check_service_app_status(settings)
                break

    if not found:
        applications.append({
            "id": client_id,
            "scopes": list(required_permissions)
        })
        changed = True
        logger.info(f"Сервисное приложение с ID {client_id} не найдено в списке сервисных приложений организации. Создаем новое.")

    if not changed:
        return True

    url = f"{DEFAULT_360_API_URL}/security/v1/org/{settings.org_id}/service_applications"
    headers = {"Authorization": f"OAuth {settings.oauth_token}"}
    payload = {"applications": applications}
    retries = 0
    try:
        while True:
            logger.debug(f"POST URL - {url}")
            response = requests.post(url, headers=headers, json=payload)
            logger.debug(f'X-Request-Id: {response.headers.get("X-Request-Id","")}')
            if response.status_code != HTTPStatus.OK.value:
                logger.error(f"Ошибка при обновлении сервисных приложений: {response.status_code}. Сообщение: {response.text}")
                if retries < MAX_RETRIES:
                    logger.error(f"Повторная попытка ({retries+1}/{MAX_RETRIES})")
                    time.sleep(RETRIES_DELAY_SEC * (retries + 1))
                    retries += 1
                else:
                    logger.error("Превышено максимальное количество попыток.")
                    return False
            else:
                if not check_service_app_response(settings, response):
                    logger.error("Не удалось настроить сервисное приложение. Проверьте настройки и повторите попытку.")
                    return False
                logger.info(f"Список сервисных приложений успешно обновлен (Client ID - {client_id}).")
                break
    except requests.exceptions.RequestException as e:
        logger.error(f"Ошибка при выполнении запроса к API: {e}")
        return False
    except Exception as e:
        logger.error(f"Неожиданная ошибка при обновлении сервисных приложений: {type(e).__name__}: {e}")
        return False

    logger.info(f"Сервисное приложение с ID {client_id} успешно настроено. Выполняем проверку валидности токена сервисного приложения...")
    return check_service_app_status(settings)
    
def delete_service_applications_list(settings: "SettingParams") -> bool:
    """
    Очищает список сервисных приложений организации.
    Спецификация API: https://yandex.ru/dev/api360/doc/ru/ref/ServiceApplicationsService/ServiceApplicationsService_Delete
    """
    url = f"{DEFAULT_360_API_URL}/security/v1/org/{settings.org_id}/service_applications"
    headers = {"Authorization": f"OAuth {settings.oauth_token}"}
    retries = 0
    try:
        while True:
            logger.debug(f"DELETE URL - {url}")
            response = requests.delete(url, headers=headers)
            logger.debug(f'X-Request-Id: {response.headers.get("X-Request-Id","")}')
            if response.status_code != HTTPStatus.OK.value:
                logger.error(f"Ошибка при очистке списка сервисных приложений: {response.status_code}. Сообщение: {response.text}")
                if retries < MAX_RETRIES:
                    logger.error(f"Повторная попытка ({retries+1}/{MAX_RETRIES})")
                    time.sleep(RETRIES_DELAY_SEC * (retries + 1))
                    retries += 1
                else:
                    logger.error("Превышено максимальное количество попыток.")
                    return False
            else:
                logger.info("Список сервисных приложений успешно очищен.")
                return True
    except requests.exceptions.RequestException as e:
        logger.error(f"Ошибка при выполнении запроса к API: {e}")
        return False
    except Exception as e:
        logger.error(f"Неожиданная ошибка при очистке списка сервисных приложений: {type(e).__name__}: {e}")
        return False

def deactivate_service_applications(settings: "SettingParams") -> bool:
    """
    Деактивирует функцию сервисных приложений.
    Спецификация API: https://yandex.ru/dev/api360/doc/ru/ref/ServiceApplicationsService/ServiceApplicationsService_Deactivate
    """
    url = f"{DEFAULT_360_API_URL}/security/v1/org/{settings.org_id}/service_applications/deactivate"
    headers = {"Authorization": f"OAuth {settings.oauth_token}"}
    retries = 0
    try:
        while True:
            logger.debug(f"POST URL - {url}")
            response = requests.post(url, headers=headers)
            logger.debug(f'X-Request-Id: {response.headers.get("X-Request-Id","")}')
            if response.status_code != HTTPStatus.OK.value:
                logger.error(f"Ошибка при деактивации сервисных приложений: {response.status_code}. Сообщение: {response.text}")
                if retries < MAX_RETRIES:
                    logger.error(f"Повторная попытка ({retries+1}/{MAX_RETRIES})")
                    time.sleep(RETRIES_DELAY_SEC * (retries + 1))
                    retries += 1
                else:
                    logger.error("Превышено максимальное количество попыток.")
                    return False
            else:
                logger.info("Сервисные приложения деактивированы.")
                return True
    except requests.exceptions.RequestException as e:
        logger.error(f"Ошибка при выполнении запроса к API: {e}")
        return False
    except Exception as e:
        logger.error(f"Неожиданная ошибка при деактивации сервисных приложений: {type(e).__name__}: {e}")
        return False

def delete_service_application_from_list(settings: "SettingParams") -> bool:
    """
    Удаляет сервисное приложение с service_app_id из списка организации.
    Если приложение единственное, очищает список и деактивирует функцию.
    """
    if not settings.service_app_id:
        logger.error("Параметр SERVICE_APP_ID не задан. Невозможно удалить сервисное приложение.")
        return False

    CHECK_TOKEN_PERMISSIONS = ["ya360_security:service_applications_read",
                               "ya360_security:service_applications_write",]
    success, data = check_token_permissions_api(settings.oauth_token)
    if not success:
        logger.error("Не удалось проверить токен (параметр OAUTH_TOKEN_ARG). Проверьте настройки.")
        return False
    token_scopes = data.get('scopes', [])
    for permission in CHECK_TOKEN_PERMISSIONS:
        if permission not in token_scopes:
            logger.error(f"В токене OAUTH_TOKEN_ARG отсутствуют необходимые права доступа ({', '.join(CHECK_TOKEN_PERMISSIONS)}) для модификации списка сервисных приложений. Проверьте настройки и повторите попытку.")
            return False

    applications, error_message = get_service_applications(settings)
    if applications is None:
        settings.service_app_status = False
        if error_message == 'feature is not active':
            return True
        else:
            return False

    if len(applications) == 0:
        logger.info("Список сервисных приложений пуст. Нечего удалять.")
        settings.service_app_status = False
        return True

    client_id = settings.service_app_id
    found = [app for app in applications if app.get("id") == client_id]
    if not found:
        logger.info(f"Сервисное приложение с ID {client_id} не найдено в списке сервисных приложений организации.")
        settings.service_app_status = False
        return False

    new_applications = [app for app in applications if app.get("id") != client_id]
    if not new_applications:
        logger.info("В списке осталось только удаляемое приложение. Очищаем список и деактивируем функцию.")
        if not delete_service_applications_list(settings):
            return False
        settings.service_app_status = False
        return deactivate_service_applications(settings)

    url = f"{DEFAULT_360_API_URL}/security/v1/org/{settings.org_id}/service_applications"
    headers = {"Authorization": f"OAuth {settings.oauth_token}"}
    payload = {"applications": new_applications}
    retries = 0
    try:
        while True:
            logger.debug(f"POST URL - {url}")
            response = requests.post(url, headers=headers, json=payload)
            logger.debug(f'X-Request-Id: {response.headers.get("X-Request-Id","")}')
            if response.status_code != HTTPStatus.OK.value:
                logger.error(f"Ошибка при обновлении списка сервисных приложений: {response.status_code}. Сообщение: {response.text}")
                if retries < MAX_RETRIES:
                    logger.error(f"Повторная попытка ({retries+1}/{MAX_RETRIES})")
                    time.sleep(RETRIES_DELAY_SEC * (retries + 1))
                    retries += 1
                else:
                    logger.error("Превышено максимальное количество попыток.")
                    return False
            else:
                logger.info(f"Сервисное приложение с ID {client_id} удалено из списка сервисных приложений организации.")
                settings.service_app_status = False
                return True
    except requests.exceptions.RequestException as e:
        logger.error(f"Ошибка при выполнении запроса к API: {e}")
        return False
    except Exception as e:
        logger.error(f"Неожиданная ошибка при обновлении списка сервисных приложений: {type(e).__name__}: {e}")
        return False

def check_service_app_status(settings: "SettingParams", skip_permissions_check: bool = False) -> bool:

    if not settings.service_app_id:
        logger.error("Параметр SERVICE_APP_ID не задан. Невозможно проверить статус сервисного приложения.")
        return False
    if not settings.service_app_secret:
        logger.error("Параметр SERVICE_APP_SECRET не задан. Невозможно проверить статус сервисного приложения.")
        return False

    if not skip_permissions_check:
        CHECK_TOKEN_PERMISSIONS = ["ya360_security:service_applications_read",]
        success, data = check_token_permissions_api(settings.oauth_token)
        if not success:
            logger.error("Не удалось проверить токен (параметр OAUTH_TOKEN_ARG). Проверьте настройки.")
            return False
        token_scopes = data.get('scopes', [])
        for permission in CHECK_TOKEN_PERMISSIONS:
            if permission not in token_scopes:
                logger.error(f"В токене OAUTH_TOKEN_ARG отсутствуют необходимые права доступа ({', '.join(CHECK_TOKEN_PERMISSIONS)}) для чтения списка сервисных приложений. Проверьте настройки и повторите попытку.")
                return False

        applications, error_message = get_service_applications(settings)
        if applications is None:
            if error_message == 'feature is not active':
                settings.service_app_status = False
                return False
            else:
                settings.service_app_status = False
                return False
        
        if len(applications) == 0:
            logger.info("Список сервисных приложений пуст. Невозможно проверить статус сервисного приложения.")
            settings.service_app_status = False
            return False

        if error_message:
            logger.error(error_message)
            settings.service_app_status = False
            return False

    # получаем первую страницу списка пользователей
    logger.info("Получение первой страницы списка всех пользователей организации из API...")
    url = f"{DEFAULT_360_API_URL}/directory/v1/org/{settings.org_id}/users"
    headers = {"Authorization": f"OAuth {settings.oauth_token}"}
    has_errors = False
    users = []
    current_page = 1
    params = {'page': current_page, 'perPage': USERS_PER_PAGE_FROM_API}
    try:
        retries = 1
        while True:
            logger.debug(f"GET URL - {url}")
            response = requests.get(url, headers=headers, params=params)
            logger.debug(f"x-request-id: {response.headers.get('x-request-id','')}")
            if response.status_code != HTTPStatus.OK.value:
                logger.error(f"!!! ОШИБКА !!! при GET запросе url - {url}: {response.status_code}. Сообщение об ошибке: {response.text}")
                if retries < MAX_RETRIES:
                    logger.error(f"Повторная попытка ({retries+1}/{MAX_RETRIES})")
                    time.sleep(RETRIES_DELAY_SEC * retries)
                    retries += 1
                else:
                    has_errors = True
                    break
            else:
                for user in response.json()['users']:
                    if not user.get('isRobot') and int(user["id"]) >= 1130000000000000:
                        users.append(user)
                logger.debug(f"Загружено {len(response.json()['users'])} пользователей.")
                break

    except requests.exceptions.RequestException as e:
        logger.error(f"!!! ERROR !!! {type(e).__name__} at line {e.__traceback__.tb_lineno} of {__file__}: {e}")
        has_errors = True

    if has_errors:
        return False

    if len(users) == 0:
        logger.error("Не найдено ни одного пользователя в организации. Невозможно проверить статус сервисного приложения.")
        return False

    # Раньше при отсутствии активных пользователей переменная user оставалась
    # неопределённой -> NameError
    user = next((u for u in users if u.get("isEnabled")), None)
    if not user:
        logger.error("Не найдено ни одного пользователя в организации. Невозможно проверить статус сервисного приложения.")
        return False
    user_email = user.get('email', '')
    try:
        user_token = get_service_app_token(settings, user_email)
    except Exception as exc:
        logger.error(f"Не удалось получить тестовый токен пользователя: {exc}")
        settings.service_app_status = False
        return False

    success, data = check_token_permissions_api(user_token)
    if not success:
        logger.error("Не удалось проверить токен пользователя. Проверьте настройки сервисного приложения.")
        return False
    token_scopes = data.get('scopes', [])
    token_org_ids = data.get('orgIds', [])
    login = data.get('login', 'unknown')

    logger.debug(f"Проверка прав доступа для токена пользователя: {login}")
    logger.debug(f"Доступные права: {token_scopes}")
    logger.debug(f"Доступные организации: {token_org_ids}")

    for permission in SERVICE_APP_PERMISSIONS:
        if permission not in token_scopes:
            logger.error(f"В токене пользователя отсутствуют необходимые права доступа {', '.join(SERVICE_APP_PERMISSIONS)}. Проверьте настройки сервисного приложения и повторите попытку.")
            settings.service_app_status = False
            return False

    logger.info("Сервисное приложение для удаления сообщений настроено корректно.")
    settings.service_app_status = True
    return True


def apply_rules_to_files_menu(settings: "SettingParams"):
    """Apply modification rules from ical_modify_rules.txt to input .ics files.

    Asks user for input and output directories, reads .ics files,
    applies modify_ics_content to each, saves results and writes a report.
    """
    modify_rules = load_modify_rules(settings)
    if not modify_rules:
        logger.error("Нет правил модификации. Проверьте файл правил и попробуйте снова.")
        return

    default_input = settings.input_dir
    input_dir = input(f"Каталог для чтения файлов [{default_input}]: ").strip()
    if not input_dir:
        input_dir = default_input

    if not os.path.isdir(input_dir):
        logger.error(f"Каталог '{input_dir}' не найден.")
        return

    default_output = "input_after_rules"
    output_dir = input(f"Каталог для вывода файлов [{default_output}]: ").strip()
    if not output_dir:
        output_dir = default_output

    # If the output directory doesn't exist, create it next to the input directory
    if not os.path.isdir(output_dir):
        parent = os.path.dirname(os.path.abspath(input_dir))
        output_dir = os.path.join(parent, output_dir)
        os.makedirs(output_dir, exist_ok=True)
        logger.info(f"Создан каталог вывода: {output_dir}")

    timestamp = datetime.now().strftime("%y%m%d_%H%M%S")
    ts_dir = os.path.join(output_dir, timestamp)
    os.makedirs(ts_dir, exist_ok=True)
    logger.info(f"Каталог для результатов: {ts_dir}")

    # Prepare report file
    rule_apply_base, rule_apply_ext = os.path.splitext(settings.rule_apply_report)
    report_name = f"{rule_apply_base}_{timestamp}{rule_apply_ext}"
    report_path = os.path.join(settings.reports_dir, report_name)
    rule_apply_writer, rule_apply_file = write_rule_apply_report_header(report_path)
    logger.info(f"Отчёт применения правил: {report_path}")

    ics_files = [
        name for name in os.listdir(input_dir)
        if name.lower().endswith(".ics")
    ]
    if not ics_files:
        logger.error(f"Нет файлов .ics в каталоге '{input_dir}'.")
        close_report_writer(rule_apply_file)
        return

    total_modified = 0
    total_files = 0

    try:
        for file_name in sorted(ics_files):
            file_path = os.path.join(input_dir, file_name)
            try:
                with open(file_path, encoding="utf-8-sig") as f:
                    ics_text = f.read()
            except OSError as exc:
                logger.error(f"Не удалось прочитать файл {file_path}: {exc}")
                continue

            modified_text, rule_changes = modify_ics_content(ics_text, modify_rules)

            # Save (modified or original) file to output directory
            out_path = os.path.join(ts_dir, file_name)
            try:
                with open(out_path, "w", encoding="utf-8", newline="") as out_f:
                    out_f.write(modified_text)
            except OSError as exc:
                logger.error(f"Не удалось сохранить файл {out_path}: {exc}")
                continue

            total_files += 1

            if rule_changes:
                total_modified += 1
                for rule_text, old_val, new_val in rule_changes:
                    rule_apply_writer.writerow([file_name, rule_text, old_val, new_val])
            else:
                # File not modified — record with empty fields
                rule_apply_writer.writerow([file_name, "", "", ""])

            logger.info(f"  {file_name}: {len(rule_changes)} изменений")
    finally:
        close_report_writer(rule_apply_file)

    logger.info(f"Обработано файлов: {total_files}, модифицировано: {total_modified}")
    logger.info(f"Результаты сохранены в: {ts_dir}")
    logger.info(f"Отчёт: {report_path}")


# ---------------------------------------------------------------------------
#  Парсинг .ics файлов в каталоге и формирование CSV-отчёта
# ---------------------------------------------------------------------------

def _parse_tz_offset_from_vtimezone(tz_block: str) -> str:
    """Extract current UTC offset from a VTIMEZONE block.

    Returns a string like '+3', '-5', '+5:30'.
    """
    lines = _unfold_ical_lines(tz_block)
    last_standard_offset = ""
    in_standard = False
    for line in lines:
        stripped = line.strip()
        if stripped == "BEGIN:STANDARD":
            in_standard = True
        elif stripped == "END:STANDARD":
            in_standard = False
        elif in_standard and line.upper().startswith("TZOFFSETTO:"):
            last_standard_offset = line.split(":", 1)[1].strip()
    if not last_standard_offset:
        return ""
    sign = last_standard_offset[0] if last_standard_offset[0] in ("+", "-") else "+"
    offset_digits = last_standard_offset.lstrip("+-")
    if len(offset_digits) == 4:
        hours = int(offset_digits[:2])
        minutes = int(offset_digits[2:])
        if minutes == 0:
            return f"{sign}{hours}"
        return f"{sign}{hours}:{minutes:02d}"
    return last_standard_offset


def _build_tz_map(ics_text: str) -> dict[str, str]:
    """Build mapping TZID -> UTC offset string from VTIMEZONE blocks."""
    tz_blocks = _extract_vtimezone_blocks(ics_text)
    tz_map: dict[str, str] = {}
    for block in tz_blocks:
        lines = _unfold_ical_lines(block)
        tzid = ""
        for line in lines:
            if line.upper().startswith("TZID:"):
                tzid = line.split(":", 1)[1].strip()
                break
        if tzid:
            tz_map[tzid] = _parse_tz_offset_from_vtimezone(block)
    return tz_map


def _extract_event_timezone(vevent_text: str, tz_map: dict[str, str]) -> str:
    """Extract timezone offset string from DTSTART of a VEVENT."""
    for line in _unfold_ical_lines(vevent_text):
        if not line.upper().startswith("DTSTART"):
            continue
        tzid_match = re.search(r"TZID=([^:;]+)", line, re.IGNORECASE)
        if tzid_match:
            tzid = tzid_match.group(1)
            return tz_map.get(tzid, tzid)
        if ":" in line:
            value = line.split(":", 1)[1].strip()
            if value.endswith("Z"):
                return "+0"
        return ""
    return ""


def _extract_organizer_display(vevent_text: str) -> str:
    """Extract organizer as 'Имя Фамилия <email>'."""
    for line in _unfold_ical_lines(vevent_text):
        if _get_ical_tag_name(line) != "organizer":
            continue
        cn = ""
        cn_match = re.search(r"CN=([^;:]+)", line, re.IGNORECASE)
        if cn_match:
            cn = cn_match.group(1).strip().strip('"')
        email = ""
        mailto_match = re.search(r"mailto:(.+)", line, re.IGNORECASE)
        if mailto_match:
            email = mailto_match.group(1).strip()
        if cn and email:
            return f"{cn} <{email}>"
        if email:
            return email
        if cn:
            return cn
        return ""
    return ""


def _extract_organizer_email(vevent_text: str) -> str:
    """Extract organizer email from ORGANIZER line (after mailto:)."""
    for line in _unfold_ical_lines(vevent_text):
        if _get_ical_tag_name(line) != "organizer":
            continue
        mailto_match = re.search(r"mailto:(.+)", line, re.IGNORECASE)
        if mailto_match:
            return mailto_match.group(1).strip().lower()
        return ""
    return ""


def _extract_organizer_cn(vevent_text: str) -> str:
    """Extract CN (common name) from ORGANIZER line."""
    for line in _unfold_ical_lines(vevent_text):
        if _get_ical_tag_name(line) != "organizer":
            continue
        cn_match = re.search(r"CN=([^;:]+)", line, re.IGNORECASE)
        if cn_match:
            return cn_match.group(1).strip().strip('"')
        return ""
    return ""


def _add_attendee_accepted_to_event(vevent_text: str, email: str, cn: str) -> str:
    """Add an attendee with PARTSTAT=ACCEPTED if not already present."""
    email_lower = email.lower()
    for line in _unfold_ical_lines(vevent_text):
        if _get_ical_tag_name(line) != "attendee":
            continue
        mailto_match = re.search(r"mailto:(.+)", line, re.IGNORECASE)
        if mailto_match and mailto_match.group(1).strip().lower() == email_lower:
            return vevent_text

    if cn:
        attendee_line = f"ATTENDEE;ROLE=REQ-PARTICIPANT;PARTSTAT=ACCEPTED;CN={cn}:mailto:{email}"
    else:
        attendee_line = f"ATTENDEE;ROLE=REQ-PARTICIPANT;PARTSTAT=ACCEPTED:mailto:{email}"

    lines = _unfold_ical_lines(vevent_text)
    result = []
    for line in lines:
        if line.strip() == "END:VEVENT":
            result.append(attendee_line)
        result.append(line)
    return "\n".join(result)


def _replace_organizer_in_event(vevent_text: str, new_email: str) -> str:
    """Replace ORGANIZER line with simple mailto-only form, removing CN and other params."""
    lines = _unfold_ical_lines(vevent_text)
    updated = []
    for line in lines:
        if _get_ical_tag_name(line) == "organizer":
            cn = new_email.rsplit("@", 1)[0]
            line = f"ORGANIZER;CN={cn}:MAILTO:{new_email}"
        updated.append(line)
    return "\n".join(updated)


def _extract_attendees_display(vevent_text: str) -> str:
    """Extract attendees as comma-separated 'Имя Фамилия <email>' strings."""
    attendees: list[str] = []
    for line in _unfold_ical_lines(vevent_text):
        if _get_ical_tag_name(line) != "attendee":
            continue
        cn = ""
        cn_match = re.search(r"CN=([^;:]+)", line, re.IGNORECASE)
        if cn_match:
            cn = cn_match.group(1).strip().strip('"')
        email = ""
        mailto_match = re.search(r"mailto:(.+)", line, re.IGNORECASE)
        if mailto_match:
            email = mailto_match.group(1).strip()
        if cn and email:
            attendees.append(f"{cn} <{email}>")
        elif email:
            attendees.append(email)
        elif cn:
            attendees.append(cn)
    return ", ".join(attendees)


def _extract_ical_property_value(vevent_text: str, prop_name: str) -> str:
    """Extract value of a specific iCal property by tag name (case-insensitive)."""
    target = prop_name.lower()
    for line in _unfold_ical_lines(vevent_text):
        if _get_ical_tag_name(line) == target and ":" in line:
            return line.split(":", 1)[1].strip()
    return ""


def _format_ical_datetime_short(value: str) -> str:
    """Convert iCal datetime '20250318T130000Z' to '18.03.25 13:00'."""
    if not value:
        return ""
    value = value.strip()
    if value.endswith("Z"):
        value = value[:-1]
    try:
        if len(value) == 8:
            dt = datetime.strptime(value, "%Y%m%d")
            return dt.strftime("%d.%m.%y")
        if len(value) >= 15:
            dt = datetime.strptime(value[:15], "%Y%m%dT%H%M%S")
            return dt.strftime("%d.%m.%y %H:%M")
    except ValueError:
        pass
    return value


def _event_has_rrule(vevent_text: str) -> bool:
    """Check if event has an RRULE property."""
    for line in _unfold_ical_lines(vevent_text):
        if _get_ical_tag_name(line) == "rrule":
            return True
    return False


def parse_ics_directory_menu(settings: SettingParams):
    """Parse all .ics files in a directory and produce a single CSV report."""
    default_dir = settings.input_dir
    dir_input = input(f"Введите имя каталога [{default_dir}]: ").strip()
    target_dir = dir_input if dir_input else default_dir

    if not os.path.isdir(target_dir):
        logger.error(f"Каталог '{target_dir}' не найден.")
        return

    ics_files = sorted(
        f for f in os.listdir(target_dir) if f.lower().endswith(".ics")
    )
    if not ics_files:
        logger.error(f"В каталоге '{target_dir}' нет файлов .ics.")
        return

    timestamp = datetime.now().strftime("%y%m%d_%H%M%S")
    report_name = f"events_{timestamp}.csv"
    os.makedirs(settings.reports_dir, exist_ok=True)
    report_path = os.path.join(settings.reports_dir, report_name)

    total_events = 0

    with open(report_path, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f, delimiter=";")
        writer.writerow([
            "file", "layer", "summary", "start", "end", "timezone",
            "repeated", "rrule", "sequence", "organizer", "participants",
            "class", "uid", "created", "modified", "url",
        ])

        for ics_file in ics_files:
            file_path = os.path.join(target_dir, ics_file)
            try:
                with open(file_path, "r", encoding="utf-8-sig") as ics_f:
                    ics_text = html.unescape(ics_f.read())
            except Exception as exc:
                logger.error(f"Ошибка чтения файла {ics_file}: {exc}")
                continue

            tz_map = _build_tz_map(ics_text)
            events = _extract_vevent_blocks(ics_text)

            for event in events:
                total_events += 1

                categories = _extract_ical_property_value(event, "categories")
                summary = _extract_summary(event).replace(";", ".")

                dtstart_raw = _extract_ical_property_value(event, "dtstart")
                dtend_raw = _extract_ical_property_value(event, "dtend")
                start_str = _format_ical_datetime_short(dtstart_raw)
                end_str = _format_ical_datetime_short(dtend_raw)

                tz_str = _extract_event_timezone(event, tz_map)

                is_recurring = _event_has_rrule(event)
                rrule_value = _extract_ical_property_value(event, "rrule")

                sequence = _extract_ical_property_value(event, "sequence")
                organizer = _extract_organizer_display(event)
                participants = _extract_attendees_display(event)
                class_value = _extract_ical_property_value(event, "class")
                uid = _extract_uid_from_event(event) or ""

                created_raw = _extract_ical_property_value(event, "created")
                created_str = _format_ical_datetime_short(created_raw)

                modified_raw = _extract_ical_property_value(event, "last-modified")
                modified_str = _format_ical_datetime_short(modified_raw)

                url = _extract_ical_property_value(event, "url")

                writer.writerow([
                    ics_file, categories, summary, start_str, end_str, tz_str,
                    str(is_recurring).lower(), rrule_value, sequence, organizer,
                    participants, class_value, uid, created_str, modified_str, url,
                ])

    logger.info(f"Обработано файлов: {len(ics_files)}, событий: {total_events}")
    logger.info(f"Отчёт сохранён: {report_path}")





def _normalize_rule_for_comparison(rule: dict) -> dict:
    """
    Нормализует правило для сравнения: оставляет только ключи condition, actions, scope.
    Ключ terminal не участвует в сравнении, так как одно и то же правило
    может отличаться только флагом terminal.
    """
    return {
        "condition": rule.get("condition"),
        "actions": rule.get("actions"),
        "scope": rule.get("scope"),
    }


def _rules_match(rule_a: dict, rule_b: dict) -> bool:
    """Сравнивает два правила по condition, actions и scope."""
    return (
        json.dumps(_normalize_rule_for_comparison(rule_a), sort_keys=True)
        == json.dumps(_normalize_rule_for_comparison(rule_b), sort_keys=True)
    )


def get_mail_routing_rules(settings: "SettingParams") -> Optional[list]:
    """
    Получает текущий список правил обработки писем организации.
    Спецификация API: https://yandex.ru/dev/api360/doc/ru/ref/RoutingService/RoutingService_GetRules

    Args:
        settings: Объект настроек с oauth_token и org_id

    Returns:
        list: Список правил, None в случае ошибки
    """
    url = f"{DEFAULT_360_API_URL}/admin/v1/org/{settings.org_id}/mail/routing/rules"
    headers = {"Authorization": f"OAuth {settings.oauth_token}"}
    retries = 0
    try:
        while True:
            logger.debug(f"GET URL - {url}")
            response = requests.get(url, headers=headers)
            logger.debug(f'X-Request-Id: {response.headers.get("X-Request-Id", "")}')
            if response.status_code != HTTPStatus.OK.value:
                logger.error(
                    f"Ошибка при получении правил обработки писем: {response.status_code}. "
                    f"Сообщение: {response.text}"
                )
                if retries < MAX_RETRIES:
                    logger.error(f"Повторная попытка ({retries + 1}/{MAX_RETRIES})")
                    time.sleep(RETRIES_DELAY_SEC * (retries + 1))
                    retries += 1
                else:
                    logger.error("Превышено максимальное количество попыток.")
                    return None
            else:
                rules = response.json().get("rules", [])
                logger.info(f"Получено правил обработки писем: {len(rules)}")
                return rules
    except requests.exceptions.RequestException as e:
        logger.error(f"Ошибка при выполнении запроса к API: {e}")
        return None
    except json.JSONDecodeError as e:
        logger.error(f"Ошибка при парсинге ответа от API: {e}")
        return None
    except Exception as e:
        logger.error(f"Неожиданная ошибка при получении правил обработки писем: {type(e).__name__}: {e}")
        return None


def list_mail_routing_rules(settings: "SettingParams") -> bool:
    """
    Получает правила обработки писем и сохраняет полный ответ API в файл
    с меткой времени в каталоге settings.reports_dir.

    Имя файла: <base>_<DDMMYY_HHMMSS><ext>, где base и ext берутся
    из settings.routing_rules_file.

    Args:
        settings: Объект настроек с oauth_token, org_id, reports_dir, routing_rules_file

    Returns:
        bool: True если файл успешно сохранён, False при ошибке
    """
    rules = get_mail_routing_rules(settings)
    if rules is None:
        logger.error("Не удалось получить правила обработки писем.")
        return False

    for rule in rules:
        print(json.dumps(rule, ensure_ascii=False, indent=4))

    data = {"rules": rules}

    if not os.path.exists(settings.reports_dir):
        os.makedirs(settings.reports_dir)

    base_name = os.path.basename(settings.routing_rules_file)
    name_root, ext = os.path.splitext(base_name)
    timestamp = datetime.now().strftime("%y%m%d_%H%M%S")
    output_filename = f"{name_root}_{timestamp}{ext}"
    output_path = os.path.join(settings.reports_dir, output_filename)

    try:
        with open(output_path, "w", encoding="utf-8") as file:
            json.dump(data, file, ensure_ascii=False, indent=2)
        logger.info(f"Правила обработки писем сохранены в файл: {output_path} (кол-во правил: {len(rules)})")
    except OSError as e:
        logger.error(f"Ошибка при записи файла {output_path}: {e}")
        return False

    return True


def set_mail_routing_rules(settings: "SettingParams", rules: list) -> bool:
    """
    Обновляет (перезаписывает) список правил обработки писем организации.
    Спецификация API: https://yandex.ru/dev/api360/doc/ru/ref/RoutingService/RoutingService_SetRules

    Args:
        settings: Объект настроек с oauth_token и org_id
        rules: Полный список правил, который будет установлен

    Returns:
        bool: True если обновление прошло успешно, False в случае ошибки
    """
    url = f"{DEFAULT_360_API_URL}/admin/v1/org/{settings.org_id}/mail/routing/rules"
    headers = {"Authorization": f"OAuth {settings.oauth_token}"}
    payload = {"rules": rules}
    retries = 0
    try:
        while True:
            logger.debug(f"PUT URL - {url}")
            logger.debug(f"Payload: {json.dumps(payload, ensure_ascii=False)}")
            response = requests.put(url, headers=headers, json=payload)
            logger.debug(f'X-Request-Id: {response.headers.get("X-Request-Id", "")}')
            if response.status_code != HTTPStatus.OK.value:
                logger.error(
                    f"Ошибка при обновлении правил обработки писем: {response.status_code}. "
                    f"Сообщение: {response.text}"
                )
                if retries < MAX_RETRIES:
                    logger.error(f"Повторная попытка ({retries + 1}/{MAX_RETRIES})")
                    time.sleep(RETRIES_DELAY_SEC * (retries + 1))
                    retries += 1
                else:
                    logger.error("Превышено максимальное количество попыток.")
                    return False
            else:
                logger.info("Правила обработки писем успешно обновлены.")
                return True
    except requests.exceptions.RequestException as e:
        logger.error(f"Ошибка при выполнении запроса к API: {e}")
        return False
    except Exception as e:
        logger.error(f"Неожиданная ошибка при обновлении правил обработки писем: {type(e).__name__}: {e}")
        return False


def _find_latest_routing_rules_file(settings: "SettingParams") -> Optional[str]:
    """
    Ищет в каталоге reports_dir последний по метке времени файл
    с базовым именем routing_rules_file (например routing_rules_*.txt).

    Returns:
        Путь к файлу или None, если подходящих файлов не найдено.
    """
    base_name = os.path.basename(settings.routing_rules_file)
    name_root, ext = os.path.splitext(base_name)
    pattern = os.path.join(settings.reports_dir, f"{name_root}_*{ext}")
    files = sorted(glob.glob(pattern))
    if not files:
        return None
    return files[-1]


def load_mail_routing_rules_from_file(settings: "SettingParams") -> bool:
    """
    Загружает правила обработки писем из JSON-файла и устанавливает их через API.

    Запрашивает у пользователя путь к файлу. По умолчанию предлагается
    последний по метке времени файл routing_rules_<DDMMYY_HHMMSS>.txt
    из каталога reports_dir.

    Args:
        settings: Объект настроек

    Returns:
        bool: True если правила успешно установлены, False при ошибке
    """
    default_file = _find_latest_routing_rules_file(settings)
    if default_file:
        prompt = f"Файл с транспортными правилами (по умочанию [{default_file}]): "
    else:
        prompt = "Файл с транспортными правилами: "

    user_input = input(prompt).strip()
    file_path = user_input if user_input else default_file

    if not file_path:
        logger.error("Имя файла не задано.")
        return False

    if not os.path.exists(file_path):
        logger.error(f"Файл не найден: {file_path}")
        return False

    try:
        with open(file_path, "r", encoding="utf-8") as f:
            raw_content = f.read()
    except OSError as e:
        logger.error(f"Ошибка при чтении файла {file_path}: {e}")
        return False

    if not raw_content.strip():
        logger.error(f"Файл пустой: {file_path}")
        return False

    try:
        payload = json.loads(raw_content)
    except json.JSONDecodeError as e:
        logger.error(f"Некорректный JSON в файле {file_path}: {e}")
        return False

    if not isinstance(payload, dict) or "rules" not in payload:
        logger.error("Некорректный формат данных: отсутствует ключ 'rules'.")
        return False

    rules = payload["rules"]
    if not isinstance(rules, list):
        logger.error("Некорректный формат данных: 'rules' должен быть списком.")
        return False

    logger.info(f"Загружено правил из файла: {len(rules)}")
    for rule in rules:
        print(json.dumps(rule, ensure_ascii=False, indent=4))

    confirm = input(f"Установить {len(rules)} правил? (y/n): ").strip().lower()
    if confirm != "y":
        logger.info("Установка правил отменена пользователем.")
        return False

    return set_mail_routing_rules(settings, rules)


def add_mail_routing_rule(settings: "SettingParams", new_rule: dict = None) -> bool:
    """
    Добавляет правило обработки писем, если такого ещё нет в списке.

    Алгоритм:
      1. Получить текущий список правил через GET.
      2. Проверить, что правило с такими же condition/actions/scope отсутствует.
      3. Если отсутствует — добавить и обновить список через PUT.

    Args:
        settings: Объект настроек с oauth_token и org_id
        new_rule: Словарь с правилом. Если не задан, используется CALDAV_EVENT_CANCEL_DROP_RULE.

    Returns:
        bool: True если правило добавлено или уже существует, False при ошибке
    """
    if new_rule is None:
        new_rule = CALDAV_EVENT_CANCEL_DROP_RULE

    rules = get_mail_routing_rules(settings)
    if rules is None:
        logger.error("Не удалось получить текущий список правил. Добавление отменено.")
        return False

    for existing_rule in rules:
        if _rules_match(existing_rule, new_rule):
            logger.info("Правило с такими условиями уже существует. Добавление не требуется.")
            return True

    rules.append(new_rule)
    logger.info(f"Добавляем новое правило. Общее количество правил: {len(rules)}")

    if not set_mail_routing_rules(settings, rules):
        logger.error("Не удалось обновить правила после добавления нового правила.")
        return False

    return True


def delete_mail_routing_rule(settings: "SettingParams", rule_to_delete: dict = None) -> bool:
    """
    Удаляет правило обработки писем с совпадающими condition/actions/scope.

    Алгоритм:
      1. Получить текущий список правил через GET.
      2. Найти правило с совпадающими condition/actions/scope.
      3. Если найдено — удалить из списка и обновить через PUT.

    Args:
        settings: Объект настроек с oauth_token и org_id
        rule_to_delete: Словарь с правилом для удаления. Если не задан, используется CALDAV_EVENT_CANCEL_DROP_RULE.

    Returns:
        bool: True если правило удалено или не было найдено, False при ошибке
    """
    if rule_to_delete is None:
        rule_to_delete = CALDAV_EVENT_CANCEL_DROP_RULE

    rules = get_mail_routing_rules(settings)
    if rules is None:
        logger.error("Не удалось получить текущий список правил. Удаление отменено.")
        return False

    original_count = len(rules)
    updated_rules = [r for r in rules if not _rules_match(r, rule_to_delete)]

    removed_count = original_count - len(updated_rules)
    if removed_count == 0:
        logger.info("Правило с указанными условиями не найдено. Удаление не требуется.")
        return True

    logger.info(f"Удаляем {removed_count} совпадающих правил. Осталось правил: {len(updated_rules)}")

    if not set_mail_routing_rules(settings, updated_rules):
        logger.error("Не удалось обновить правила после удаления.")
        return False

    return True

def main_menu(settings: "SettingParams"):
    actions = {
        "1": ("Выгрузить события из Яндекс 360 Календаря.", export_menu_parallel),
        "2": ("Выгрузить события из внешнего сервера CalDAV.", export_from_external_caldav_server),
        "3": ("Импортировать все события.", import_menu_parallel),
        "4": ("Вывести список слоёв календарей пользователей.", list_calendars_for_user),
        "5": ("Парсинг .ics файлов в каталоге (CSV-отчёт).", parse_ics_directory_menu),
        "6": ("Применить правила модификации к файлам .ics.", apply_rules_to_files_menu),
        # Раньше этот пункт был недостижим: в main_menu стояли две ветки choice == "3"
        "7": ("Импортировать все события для всех пользователей без вопросов (новый UID при конфликте).",
              import_menu_parallel_without_params),
        "8": ("Настроить правила обработки писем для блокировки уведомлений удаления событий.", mail_routing_rules_menu),
        "9": ("Настройка сервисного приложения.", service_application_status_menu),
    }
    hidden_actions = {
        "666": delete_menu_parallel,
    }
    while True:
        print("\n")
        print("Выберите опцию:")
        for key, (title, _func) in actions.items():
            print(f"{key}. {title}")
        print("0. (Ctrl+C) Выход")
        print("\n")
        choice = input("Введите ваш выбор (0-9): ").strip()

        if choice == "0":
            print("До свидания!")
            break
        func = actions[choice][1] if choice in actions else hidden_actions.get(choice)
        if func is None:
            logger.error("Неверный выбор. Попробуйте снова.")
            continue
        # Ошибка в одном пункте меню больше не завершает скрипт целиком
        try:
            func(settings)
        except KeyboardInterrupt:
            raise
        except Exception as exc:
            tb = traceback.extract_tb(exc.__traceback__)
            last_frame = tb[-1] if tb else None
            location = f" at {last_frame.filename}:{last_frame.lineno} in {last_frame.name}" if last_frame else ""
            logger.error(f"{type(exc).__name__}{location}: {exc}")
            logger.debug(traceback.format_exc())


def service_application_status_menu(settings: SettingParams):
    while True:
        print("\n")
        print("------------------------ Сервисное приложение ------------------------")
        print("1. Проверить статус сервисного приложения.")
        print("2. Настроить сервисное приложение.")
        print("3. Удаление сервисного приложения из списка организации.")
        print("4. Выгрузить данные сервисных приложений в файл.")
        print("5. Загрузить параметры сервисных приложений из файла.")
        print("------------------------ Выйти в главное меню -------------------------")
        print("0. Выйти в главное меню.")
        choice = input("Введите ваш выбор (0-5): ")
        if choice == "0" or choice == "":
            break
        elif choice == "1":
            check_service_app_status(settings)
        elif choice == "2":
            setup_service_application(settings)
        elif choice == "3":
            delete_service_application_from_list(settings)
        elif choice == "4":
            export_service_applications_api_data(settings)
        elif choice == "5":
            import_service_applications_api_data(settings)
        else:
            print("Неверный выбор. Попробуйте снова.")
    return settings

def mail_routing_rules_menu(settings: SettingParams):
    while True:
        print("\n")
        print("------------------------ Правила обработки писем ------------------------")
        print("1. Вывести список транспортных правил обработки писем в файл.")
        print("2. Загрузить транспортные правила обработки писем из файла.")
        print("3. Добавить правило обработки писем для блокировки уведомлений удаления событий.")
        print("4. Удалить правило обработки писем для блокировки уведомлений удаления событий.")
        print("------------------------ Выйти в главное меню -------------------------")
        print("0. Выйти в главное меню.")
        choice = input("Введите ваш выбор (0-4): ")
        if choice == "0" or choice == "":
            break
        elif choice == "1":
            list_mail_routing_rules(settings)
        elif choice == "2":
            load_mail_routing_rules_from_file(settings)
        elif choice == "3":
            add_mail_routing_rule(settings)
        elif choice == "4":
            delete_mail_routing_rule(settings)


if __name__ == "__main__":
    denv_path = os.path.join(os.path.dirname(__file__), ".env")
    if os.path.exists(denv_path):
        load_dotenv(dotenv_path=denv_path, verbose=True, override=True)
    else:
        logger.error("Не найден файл .env. Выход.")
        sys.exit(EXIT_CODE)

    logger.info("\n")
    logger.info("---------------------------------------------------------------------------.")
    logger.info("Запуск скрипта.")

    settings = get_settings()
    if settings is None:
        logger.error("Проверьте настройки в файле .env и попробуйте снова.")
        sys.exit(EXIT_CODE)

    try:
        main_menu(settings)
    except KeyboardInterrupt:
        logger.info("\nCtrl+C pressed. До свидания!")
        sys.exit(EXIT_CODE)
    except Exception as exc:
        tb = traceback.extract_tb(exc.__traceback__)
        last_frame = tb[-1] if tb else None
        if last_frame:
            logger.error(f"{type(exc).__name__} at {last_frame.filename}:{last_frame.lineno} in {last_frame.name}: {exc}")
        else:
            logger.error(f"{type(exc).__name__}: {exc}")
        sys.exit(EXIT_CODE)

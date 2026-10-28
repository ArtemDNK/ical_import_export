# ExchangeCalendarMigrator

Консольное приложение для экспорта календарей из Microsoft Exchange в формат ICS. Позволяет массово выгружать события календаря из нескольких почтовых ящиков с использованием учётной записи администратора.

## Возможности

- Подключение к Exchange через Autodiscover или напрямую по EWS URL
- Массовый экспорт календарей из списка почтовых ящиков
- Автоматическое разбиение больших календарей на несколько ICS-файлов
- Поддержка повторяющихся событий
- Сохранение информации об организаторе и участниках
- Параллельная обработка нескольких ящиков

## Требования

- ОС Windows
- Exchange версии 2013 или выше
- Учётная запись с правами доступа к почтовым ящикам (см. раздел "Настройка прав доступа")

## Конфигурация (config.cfg)

| Параметр | Описание | Пример |
|----------|----------|--------|
| `audiscovery_url` (или `autodiscover_url`) | URL службы Autodiscover. Оставить пустым для использования `ews_url` | `https://autodiscover.example.com/autodiscover/autodiscover.xml` |
| `ews_url` | Прямой URL Exchange Web Services (используется если Autodiscover недоступен) | `https://mail.example.com/EWS/Exchange.asmx` |
| `input_file` | Путь к файлу со списком почтовых ящиков | `input_mailboxes.txt` |
| `output_dir` | Каталог для сохранения ICS-файлов (создаётся автоматически) | `output` |
| `superadmin` | Email учётной записи с правами доступа к ящикам | `admin@example.com` |
| `superadmin_pass` | Пароль учётной записи | `P@ssw0rd!` |
| `days_ago` | За сколько дней назад выгружать события (по умолчанию `30`). Для будущих дат выгружаются события на год вперёд | `30` |
| `file_max_size` | Максимальный размер одного ICS-файла в мегабайтах | `10` |
| `allow_untrusted_connections` | Разрешить подключения к серверам с недоверенными SSL-сертификатами (`true`/`false`) | `true` |
| `exchange_timezone_shift` | Смещение часового пояса Exchange относительно UTC (поддерживаются и смещения с минутами) | `+3`, `-5` или `+5:30` |

>[!WARNING]
> При импорте ICS файлов в Яндекс 360 размер каждого файла не должен превышать 10 Мб

## Формат файла input_mailboxes.txt

Текстовый файл со списком SMTP-адресов почтовых ящиков для экспорта. Каждый адрес на отдельной строке:

```
user1@domain.ru
user2@domain.ru
user3@domain.ru
```

- Пустые строки игнорируются
- Дубликаты автоматически удаляются
- Регистр не учитывается

## Настройка прав доступа в Exchange

### Выдача доступа через Fill Mailbox Access

Для работы приложения учётной записи `superadmin` необходимо предоставить права **Full Access** на все почтовые ящики, из которых будет выполняться экспорт.

#### Exchange Management Shell

Для добавления прав доступа к одному ящику:

```powershell
Add-MailboxPermission -Identity "user@domain.ru" -User "admin@domain.ru" -AccessRights FullAccess -InheritanceType All
```

Для добавления прав доступа ко всем ящикам в организации:

```powershell
Get-Mailbox -ResultSize Unlimited | Add-MailboxPermission -User "admin@domain.ru" -AccessRights FullAccess -InheritanceType All -AutoMapping $false
```

Параметр `-AutoMapping $false` предотвращает автоматическое добавление всех ящиков в Outlook администратора.

#### Проверка прав доступа

Проверить текущие права на ящик:

```powershell
Get-MailboxPermission -Identity "user@domain.ru" | Where-Object { $_.User -like "*admin*" }
```

#### Удаление прав доступа

При необходимости удалить ранее выданные права:

```powershell
Remove-MailboxPermission -Identity "user@domain.ru" -User "admin@domain.ru" -AccessRights FullAccess -Confirm:$false
```

Для удаления прав со всех ящиков:

```powershell
Get-Mailbox -ResultSize Unlimited | Remove-MailboxPermission -User "admin@domain.ru" -AccessRights FullAccess -Confirm:$false
```

### Выдача доступа через Application Impersonation

Альтернативный способ — использование роли **ApplicationImpersonation**. Этот метод позволяет сервисной учётной записи выполнять действия от имени других пользователей без предоставления Full Access на каждый ящик.

#### Вариант 1: Доступ ко всем ящикам организации

```powershell
New-ManagementRoleAssignment -Name "AppImpersonation-<account>" -Role "ApplicationImpersonation" -User "<domain>\<account>"
```

Пример:

```powershell
New-ManagementRoleAssignment -Name "AppImpersonation-svcEws" -Role "ApplicationImpersonation" -User "DOMAIN\svcEws"
```

Проверка назначенных прав:

```powershell
Get-ManagementRoleAssignment -Role "ApplicationImpersonation" -GetEffectiveUsers |
    Where-Object { $_.EffectiveUserName -like "*svcEws*" } |
    Format-Table Name, Role, EffectiveUserName
```

#### Вариант 2: Ограничение доступа определённой группой ящиков (рекомендуется)

Этот вариант более безопасен, так как ограничивает impersonation только указанными почтовыми ящиками.

**Шаг 1.** Создайте security group и добавьте в неё нужные ящики:

```powershell
New-DistributionGroup -Name "ImpersonationScopeGroup" -Type Security
```

**Шаг 2.** Создайте management scope по членству в группе:

```powershell
New-ManagementScope -Name "ImpersonationScope" -RecipientRestrictionFilter "MemberOfGroup -eq 'CN=ImpersonationScopeGroup,OU=Groups,DC=domain,DC=ru'"
```

**Шаг 3.** Назначьте роль с ограничением по scope:

```powershell
New-ManagementRoleAssignment -Name "AppImp-svcEws-Scoped" -Role "ApplicationImpersonation" -User "DOMAIN\svcEws" -CustomRecipientWriteScope "ImpersonationScope"
```

#### Примечания

- Учётная запись не обязательно должна быть mail-enabled — достаточно AD-аккаунта. Обычно используется сервисная AD-учётка без mailbox.
- Изменения обычно применяются быстро, но иногда требуется перелогин или обновление токена (закрыть/открыть сессию). В редких случаях может потребоваться подождать несколько минут.

## Использование

1. Скопируйте ExchangeCalendarMigrator.exe, config.cfg, input_mailboxes.txt из каталога [publish](https://github.com/alavret/ews2ya360/tree/main/ExchangeCalendarMigrator/Publish) в каталог на компюьтере с ОС Windows который имеет доступ по сети к Exchange серверу.
2. Создайте каталог, куда будет выгружаться список ics файлов.
3. Отредактируйте `config.cfg`, указав параметры подключения к Exchange
4. Создайте или отредактируйте файл `input_mailboxes.txt` со списком ящиков для экспорта
5. Запустите `ExchangeCalendarMigrator.exe`
6. Экспортированные ICS-файлы будут сохранены в каталоге, указанном в параметре `output_dir`

## Выходные файлы

Для каждого почтового ящика создаётся один или несколько ICS-файлов в формате:

```
{email}_{номер}.ics
```

Например: `user@domain.ru_1.ics`, `user@domain.ru_2.ics`

Разбиение на несколько файлов происходит при превышении лимита `file_max_size`.

## Логирование

Приложение ведёт лог в файл `export_ics.log` в директории запуска. Лог содержит информацию о ходе экспорта, предупреждения и ошибки.

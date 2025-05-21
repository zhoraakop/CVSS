const mongoose = require("mongoose");
const Vulnerability = require("../models/Vulnerability");
const connectDB = require("./DB");

const vulnerabilitiesData = [
  {
    zapPluginId: "0",
    name: "Просмотр Каталога",
    description: "-",
    cvssScore: 0,
    riskLevel: "Средний",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation: "Отключите просмотр каталогов.",
  },
  {
    zapPluginId: "2",
    name: "Раскрытие частной интеллектуальной собственности",
    description: "-",
    cvssScore: 0,
    riskLevel: "Низкий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N/E:U",
    recommendation: "Удалите частный IP-адрес из тела HTTP-ответа.",
  },
  {
    zapPluginId: "3-1",
    name: "Идентификатор сеанса в URL-адресе перезаписывается",
    description: "-",
    cvssScore: 0,
    riskLevel: "Средний",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Для обеспечения безопасности содержимого поместите идентификатор сеанса в файл cookie. ",
  },
  {
    zapPluginId: "3-2",
    name: "Идентификатор сеанса в URL-адресе перезаписывается",
    description: "-",
    cvssScore: 0,
    riskLevel: "Средний",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Для обеспечения безопасности содержимого поместите идентификатор сеанса в файл cookie. ",
  },
  {
    zapPluginId: "3-3",
    name: "Реферер предоставляет идентификатор сеанса",
    description: "-",
    cvssScore: 0,
    riskLevel: "Средний",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Для безопасного контента поместите идентификатор сеанса в защищённый файл cookie сеанса.",
  },
  {
    zapPluginId: "6-1",
    name: "Прохождение пути",
    description: "-",
    cvssScore: 0,
    riskLevel: "Высокий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Используйте стратегию проверки входных данных «принимать только то, что известно как хорошее», то есть используйте список допустимых входных данных, которые строго соответствуют спецификациям. Отклоняйте любые входные данные, которые не соответствуют спецификациям, или преобразуйте их в соответствии со спецификациями. ",
  },
  {
    zapPluginId: "6-2",
    name: "Прохождение пути",
    description: "-",
    cvssScore: 0,
    riskLevel: "Высокий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Используйте стратегию проверки входных данных «принимать только то, что известно как хорошее», то есть используйте список допустимых входных данных, которые строго соответствуют спецификациям. Отклоняйте любые входные данные, которые не соответствуют спецификациям, или преобразуйте их в соответствии со спецификациями. ",
  },
  {
    zapPluginId: "6-3",
    name: "Прохождение пути",
    description: "-",
    cvssScore: 0,
    riskLevel: "Высокий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Используйте стратегию проверки входных данных «принимать только то, что известно как хорошее», то есть используйте список допустимых входных данных, которые строго соответствуют спецификациям. Отклоняйте любые входные данные, которые не соответствуют спецификациям, или преобразуйте их в соответствии со спецификациями. ",
  },
  {
    zapPluginId: "6-4",
    name: "Прохождение пути",
    description: "-",
    cvssScore: 0,
    riskLevel: "Высокий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Используйте стратегию проверки входных данных «принимать только то, что известно как хорошее», то есть используйте список допустимых входных данных, которые строго соответствуют спецификациям. Отклоняйте любые входные данные, которые не соответствуют спецификациям, или преобразуйте их в соответствии со спецификациями. ",
  },
  {
    zapPluginId: "6-5",
    name: "Прохождение пути",
    description: "-",
    cvssScore: 0,
    riskLevel: "Высокий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Используйте стратегию проверки входных данных «принимать только то, что известно как хорошее», то есть используйте список допустимых входных данных, которые строго соответствуют спецификациям. Отклоняйте любые входные данные, которые не соответствуют спецификациям, или преобразуйте их в соответствии со спецификациями. ",
  },
  {
    zapPluginId: "7",
    name: "Удаленное включение файла",
    description: "-",
    cvssScore: 0,
    riskLevel: "Высокий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    recommendation:
      "Когда набор допустимых объектов, таких как имена файлов или URL-адреса, ограничен или известен, создайте сопоставление между набором фиксированных входных значений (например, числовых идентификаторов) и фактическими именами файлов или URL-адресами и отклоняйте все остальные входные данные. Например, идентификатор 1 может сопоставляться с «inbox.txt», а идентификатор 2 — с «profile.txt». Такие функции, как ESAPI AccessReferenceMap, предоставляют такую возможность.",
  },
  {
    zapPluginId: "41",
    name: "Раскрытие исходного кода - Git",
    description: "Исходный код текущей страницы был раскрыт веб-сервером.",
    cvssScore: 0,
    riskLevel: "Высокий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Убедитесь, что файлы метаданных Git не развёрнуты на веб-сервере или сервере приложений.",
  },
  {
    zapPluginId: "42",
    name: "Раскрытие исходного кода - SVN",
    description: "Исходный код текущей страницы был раскрыт веб-сервером.",
    cvssScore: 0,
    riskLevel: "Средний",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Убедитесь, что файлы метаданных SVN не развёрнуты на веб-сервере или сервере приложений.",
  },
  {
    zapPluginId: "43",
    name: "Раскрытие исходного кода - Включение файла",
    description:
      "Метод атаки «Обход пути» позволяет злоумышленнику получить доступ к файлам, каталогам и командам, которые потенциально находятся за пределами корневого каталога веб-документа.",
    cvssScore: 0,
    riskLevel: "Высокий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Предположим, что все входные данные являются вредоносными. Используйте стратегию проверки входных данных «принимать только то, что известно как хорошее», то есть используйте список допустимых входных данных, которые строго соответствуют спецификациям. Отклоняйте любые входные данные, которые не соответствуют спецификациям, или преобразуйте их в соответствии со спецификациями. ",
  },
  {
    zapPluginId: "10003",
    name: "Уязвимая библиотека JS",
    description: "Идентифицированная библиотека, по-видимому, уязвима.",
    cvssScore: 0,
    riskLevel: "Средний",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    recommendation: "Обновите затронутую библиотеку до последней версии.",
  },
  {
    zapPluginId: "10004",
    name: "Пассивный сканер технического обнаружения",
    description:
      "Была определена следующая технология “Виджетов”: Пример программного обеспечения.",
    cvssScore: 0,
    riskLevel: "Информационный",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Информационная уязвимость не представляет непосредственной угрозы, но может раскрывать данные, полезные для потенциального атакующего. Рекомендуется скрыть лишнюю техническую информацию (заголовки сервера, сообщения об ошибках, конфигурационные файлы), ограничить доступ к служебным директориям и установить безопасные флаги для cookie. Следует регулярно проводить аудит конфигураций и устранять избыточную информацию в ответах сервера.",
  },
  {
    zapPluginId: "10009",
    name: "Утечка информации о Баннере на странице",
    description:
      "Сервер вернул строку с информацией о версии в содержимом ответа. Утечка такой информации может позволить злоумышленникам в дальнейшем ориентироваться на конкретные проблемы, связанные с используемым продуктом и версией.",
    cvssScore: 0,
    riskLevel: "Низкий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N/E:U",
    recommendation:
      "Настройте сервер так, чтобы предотвратить утечку такой информации. Например, в Tomcat это делается с помощью директивы «server» и реализации пользовательских страниц ошибок. В Apache это делается с помощью директив «ServerSignature» и «ServerTokens».",
  },
  {
    zapPluginId: "10010",
    name: "Cookie No HttpOnly Flag",
    description:
      "Файл cookie был создан без флага HttpOnly, что означает, что к файлу cookie может получить доступ JavaScript. ",
    cvssScore: 5.3,
    riskLevel: "Низкий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N/E:U",
    recommendation: "Добавьте атрибут HttpOnly для всех cookies",
  },
  {
    zapPluginId: "10011",
    name: "Файл cookie без атрибута Secure",
    description:
      "Файл cookie был создан без флага безопасности, что означает, что к нему можно получить доступ через незашифрованные соединения.",
    cvssScore: 0,
    riskLevel: "Низкий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N/E:U",
    recommendation: "Добавьте атрибут Secure для всех cookies",
  },
  {
    zapPluginId: "10015",
    name: "Re-examine Cache-control Directives",
    description:
      "Заголовок cache-control не установлен должным образом или отсутствует, что позволяет браузеру и прокси-серверам кэшировать контент.",
    cvssScore: 0,
    riskLevel: "Информационный",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Для безопасного контента убедитесь, что в HTTP-заголовке cache-control установлено значение 'no-cache, no-store, must-revalidate'. ",
  },
  {
    zapPluginId: "10016",
    name: "Защита XSS веб-браузера не включена",
    description:
      "Защита веб-браузера от XSS не включена или отключена в конфигурации заголовка ответа HTTP «X-XSS-Protection» на веб-сервере.",
    cvssScore: 0,
    riskLevel: "Информационный",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
    recommendation: "Больше широко не поддерживается браузерами.",
  },
  {
    zapPluginId: "10017",
    name: "Cross-Domain JavaScript Source File Inclusion",
    description:
      "Страница содержит один или несколько файлов скриптов из стороннего домена.",
    cvssScore: 0,
    riskLevel: "Низкий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N/E:U",
    recommendation:
      "Убедитесь, что исходные файлы JavaScript загружаются только из надёжных источников, которые не могут контролироваться конечными пользователями приложения. ",
  },
  {
    zapPluginId: "10019-1",
    name: "Отсутствует заголовок типа Content-Type",
    description: "Заголовок Content-Type был либо отсутствующим, либо пустым.",
    cvssScore: 0,
    riskLevel: "Информационный",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Убедитесь, что на каждой странице задано конкретное и подходящее значение Content-Type для отображаемого контента.",
  },
  {
    zapPluginId: "10019-2",
    name: "Заголовок типа Content-Type пуст",
    description: "Заголовок Content-Type был либо отсутствующим, либо пустым.",
    cvssScore: 0,
    riskLevel: "Информационный",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Убедитесь, что на каждой странице задано конкретное и подходящее значение Content-Type для отображаемого контента.",
  },
  {
    zapPluginId: "10020-1",
    name: "Missing Anti-clickjacking Header",
    description:
      "Ответ не защищает от атак «кликджекинга». Он должен включать либо директиву Content-Security-Policy с параметром «frame-ancestors», либо X-Frame-Options.",
    cvssScore: 0,
    riskLevel: "Средний",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Современные веб-браузеры поддерживают HTTP-заголовки Content-Security-Policy и X-Frame-Options. Убедитесь, что один из них установлен на всех веб-страницах, возвращаемых вашим сайтом/приложением.",
  },
  {
    zapPluginId: "10020-2",
    name: "Несколько записей заголовка X-Frame-Options",
    description:
      "Были обнаружены заголовки X-Frame-Options (XFO). Ответ с несколькими записями в заголовке XFO может непредсказуемым образом обрабатываться всеми пользовательскими агентами.",
    cvssScore: 0,
    riskLevel: "Средний",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Убедитесь, что в ответе присутствует только один заголовок X-Frame-Options.",
  },
  {
    zapPluginId: "10020-3",
    name: "X-Frame-Options, заданные с помощью META (не соответствуют спецификации)",
    description:
      "Были обнаружены заголовки X-Frame-Options (XFO). Ответ с несколькими записями в заголовке XFO может непредсказуемым образом обрабатываться всеми пользовательскими агентами.",
    cvssScore: 0,
    riskLevel: "Средний",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Убедитесь, что X-Frame-Options задано в поле заголовка ответа. В качестве альтернативы рассмотрите возможность реализации директивы «frame-ancestors» в политике безопасности контента.",
  },
  {
    zapPluginId: "10020-4",
    name: "X-Frame-Options настройки искажены",
    description:
      "В ответе присутствовал заголовок X-Frame-Options, но его значение было задано неправильно.",
    cvssScore: 0,
    riskLevel: "Средний",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Убедитесь, что на всех веб-страницах, возвращаемых вашим сайтом, используется правильный параметр (если вы ожидаете, что страница будет помещена в рамку только страницами с вашего сервера (например, она является частью FRAMESET), то вам следует использовать SAMEORIGIN, в противном случае, если вы не ожидаете, что страница будет помещена в рамку, вам следует использовать DENY.",
  },
  {
    zapPluginId: "10021",
    name: "X-Content-Type-Options Header Missing",
    description:
      "Для заголовка Anti-MIME-Sniffing X-Content-Type-Options не было установлено значение «nosniff». Это позволяет более старым версиям Internet Explorer и Chrome выполнять MIME-анализ содержимого ответа, что может привести к тому, что содержимое ответа будет интерпретировано и отображено как тип контента, отличный от заявленного типа контента. ",
    cvssScore: 3.5,
    riskLevel: "Низкий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N/E:U",
    recommendation:
      "Убедитесь, что сервер приложений/веб-сервер правильно устанавливает заголовок Content-Type и что для всех веб-страниц установлен заголовок X-Content-Type-Options со значением «nosniff». ",
  },
  {
    zapPluginId: "10023",
    name: "Раскрытие информации - сообщения об ошибках отладки",
    description:
      "Ответ, по-видимому, содержал общие сообщения об ошибках, возвращаемые такими платформами, как ASP.NET, и веб-серверами, такими как IIS и Apache. Вы можете настроить список общих сообщений об ошибках.",
    cvssScore: 0,
    riskLevel: "Низкий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N/E:U",
    recommendation:
      "Отключите отладочные сообщения перед запуском в производство.",
  },
  {
    zapPluginId: "10024",
    name: "Раскрытие информации - конфиденциальная информация в URL",
    description:
      "Похоже, что запрос содержит конфиденциальную информацию, которая была передана в URL-адресе. Это может нарушать требования PCI и большинство организационных политик. ",
    cvssScore: 0,
    riskLevel: "Информационный",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation: "Не передавайте конфиденциальную информацию в URL.",
  },
  {
    zapPluginId: "10025",
    name: "Раскрытие информации - конфиденциальная информация в заголовке HTTP-реферера",
    description:
      "В заголовке HTTP мог быть передан потенциально конфиденциальный параметр другому домену. Это может нарушить политику PCI и большинство организационных политик.",
    cvssScore: 0,
    riskLevel: "Информационный",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation: "Не передавайте конфиденциальную информацию в URL.",
  },
  {
    zapPluginId: "10026",
    name: "Переопределение параметра HTTP",
    description:
      "Неопределённое действие формы: потенциально возможна атака с подменой параметров HTTP. Это известная проблема с Java-сервлетами, но и другие платформы могут быть уязвимы.",
    cvssScore: 0,
    riskLevel: "Средний",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N",
    recommendation: "Во всех формах должен быть указан URL-адрес действия.",
  },
  {
    zapPluginId: "10027",
    name: "Information Disclosure - Suspicious Comments",
    description:
      "Похоже, что ответ содержит подозрительные комментарии, которые могут помочь злоумышленнику.",
    cvssScore: 0,
    riskLevel: "Информационный",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Удалите все комментарии, которые возвращают информацию, которая может помочь злоумышленнику, и устраните все проблемы, на которые они ссылаются.",
  },
  {
    zapPluginId: "10028",
    name: "Открытое перенаправление",
    description:
      "Эта проверка анализирует вводимые пользователем данные в параметрах строки запроса и POST-данных, чтобы определить, где возможны открытые перенаправления. Открытые перенаправления возникают, когда приложение позволяет вводить данные пользователем для управления перенаправлением на другой сайт. ",
    cvssScore: 0,
    riskLevel: "Высокий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Чтобы избежать уязвимости при открытом перенаправлении, параметры сценария/программы приложения должны быть проверены перед отправкой кода 302 HTTP (перенаправление) в браузер клиента. Реализуйте функцию безопасного перенаправления, которая перенаправляет только на относительные URI или список доверенных доменов.",
  },
  {
    zapPluginId: "10029",
    name: "Отравление cookie",
    description:
      "Эта проверка рассматривает вводимые пользователем данные в параметрах строки запроса и POST-данных, чтобы определить, где можно контролировать параметры файлов cookie. Это называется атакой с использованием файлов cookie и становится возможной, когда злоумышленник может манипулировать файлами cookie различными способами.",
    cvssScore: 0,
    riskLevel: "Информационный",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Не позволяйте пользователям вводить данные для управления именами и значениями файлов cookie. Если некоторые параметры строки запроса необходимо задать в значениях файлов cookie, обязательно отфильтруйте точки с запятой, которые могут служить разделителями пар имя/значение.",
  },
  {
    zapPluginId: "10030",
    name: "Кодировка, управляемая пользователем",
    description:
      "Эта проверка рассматривает вводимые пользователем данные в параметрах строки запроса и POST-данных, чтобы определить, где пользователь может управлять объявлением кодировки Content-Type или метатега.",
    cvssScore: 0,
    riskLevel: "Информационный",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Используйте UTF-8 во всех объявлениях кодировки. Если для выбора кодировки требуется ввод данных пользователем, убедитесь, что используется только разрешенный список.",
  },
  {
    zapPluginId: "10031",
    name: "User Controllable HTML Element Attribute (Potential XSS)",
    description:
      "Эта проверка рассматривает вводимые пользователем данные в параметрах строки запроса и POST-данных, чтобы определить, где могут контролироваться определённые значения атрибутов HTML. ",
    cvssScore: 0,
    riskLevel: "Информационный",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Проверяйте все вводимые данные и очищайте их перед записью в любые атрибуты HTML.",
  },
  {
    zapPluginId: "10032-1",
    name: "Потенциальные IP-адреса, найденные в Viewstate",
    description:
      "Было обнаружено, что следующие потенциальные IP-адреса сериализуются в поле viewstate.",
    cvssScore: 0,
    riskLevel: "Средний",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Убедитесь, что предоставленная информация не является конфиденциальной.",
  },
  {
    zapPluginId: "10032-2",
    name: "Электронные письма, найденные в Viewstate",
    description:
      "Было обнаружено, что следующие электронные письма сериализуются в поле viewstate.",
    cvssScore: 0,
    riskLevel: "Средний",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Убедитесь, что предоставленная информация не является конфиденциальной.",
  },
  {
    zapPluginId: "10032-3",
    name: "Старая Asp.Net используемая версия",
    description: "На этом сайте используется ASP.NET версии 1.0 или 1.1.",
    cvssScore: 0,
    riskLevel: "Низкий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N/E:U",
    recommendation:
      "Убедитесь, что платформа engaged Framework по-прежнему поддерживается корпорацией Майкрософт.",
  },
  {
    zapPluginId: "10032-4",
    name: "Состояние просмотра без подписи MAC(не точно)",
    description:
      "Этот сайт использует состояние просмотра ASP.NET, но, возможно, без MAC-адреса.",
    cvssScore: 0,
    riskLevel: "Высокий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Убедитесь, что MAC установлен для всех страниц этого веб-сайта.",
  },
  {
    zapPluginId: "10032-5",
    name: "Состояние просмотра без подписи MAC(точно)",
    description:
      "Этот веб-сайт использует Viewstate от ASP.NET, но без какого-либо MAC.",
    cvssScore: 0,
    riskLevel: "Высокий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Убедитесь, что MAC установлен для всех страниц этого веб-сайта.",
  },
  {
    zapPluginId: "10032-6",
    name: "Разделенное состояние просмотра в использовании",
    description:
      "Этот веб-сайт использует Viewstate от ASP.NET, но без какого-либо MAC.",
    cvssScore: 0,
    riskLevel: "Информационный",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Нет — возможно, ребята, которые управляют сервером, настроили конфигурацию, так как это не настройка по умолчанию.",
  },
  {
    zapPluginId: "10033",
    name: "Просмотр каталога",
    description:
      "Можно просмотреть список содержимого каталога. В списке содержимого каталога могут быть скрытые скрипты, файлы-заготовки, исходные файлы резервных копий и т. д., доступ к которым может раскрыть конфиденциальную информацию.",
    cvssScore: 0,
    riskLevel: "Средний",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Настройте веб-сервер так, чтобы отключить просмотр каталогов.",
  },
  {
    zapPluginId: "10034",
    name: "Уязвимость Heartbleed OpenSSL",
    description:
      "Реализация TLS и DTLS в OpenSSL 1.0.1 до версии 1.0.1g некорректно обрабатывает пакеты Heartbeat Extension, что позволяет удалённым злоумышленникам получать конфиденциальную информацию из памяти процесса с помощью специально созданных пакетов, которые вызывают переполнение буфера и могут привести к раскрытию конфиденциальной информации.",
    cvssScore: 0,
    riskLevel: "Высокий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:H/SC:N/SI:N/SA:N",
    recommendation:
      "Обновите до версии OpenSSL 1.0.1g или более поздней. Перевыпустите сертификаты HTTPS. Измените асимметричные закрытые ключи и общие секретные ключи.",
  },
  {
    zapPluginId: "10035-1",
    name: "Strict-Transport-Security Header Not Set",
    description:
      "HTTP Strict Transport Security (HSTS) — это механизм политики веб-безопасности, с помощью которого веб-сервер объявляет, что соответствующие пользовательские агенты должны взаимодействовать с ним только по защищённому протоколу HTTPS",
    cvssScore: 0,
    riskLevel: "Низкий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N/E:U",
    recommendation:
      "Убедитесь, что ваш веб-сервер, сервер приложений, балансировщик нагрузки и т. д. настроены на использование Strict-Transport-Security.",
  },
  {
    zapPluginId: "10035-2",
    name: "Заголовок Strict-Transport-Security не установлен",
    description:
      "Был обнаружен заголовок HTTP Strict Transport Security (HSTS), но он содержит директиву max-age=0, которая отключает контроль и указывает браузерам сбросить все предыдущие настройки, связанные с HSTS.",
    cvssScore: 0,
    riskLevel: "Низкий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N/E:U",
    recommendation:
      "Просмотрите конфигурацию этого элемента управления. Убедитесь, что ваш веб-сервер, сервер приложений, балансировщик нагрузки и т. д. настроены на установку Strict-Transport-Security с соответствующим значением max-age.",
  },
  {
    zapPluginId: "10035-3",
    name: "Несколько записей в заголовке Strict-Transport-Security (не соответствует спецификации)",
    description:
      "Были обнаружены заголовки HTTP Strict Transport Security (HSTS). Ответ с несколькими записями заголовков HSTS не соответствует спецификации (RFC 6797), и будет обработан только первый заголовок HSTS, остальные будут проигнорированы пользовательскими агентами, или политика HSTS может быть применена неправильно.",
    cvssScore: 0,
    riskLevel: "Низкий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N/E:U",
    recommendation:
      "Убедитесь, что только один компонент в вашем стеке: код, веб-сервер, сервер приложений, балансировщик нагрузки и т. д. настроен на установку или добавление заголовка HTTP Strict-Transport-Security (HSTS).",
  },
  {
    zapPluginId: "10035-4",
    name: "Заголовок Strict-Transport-Security в обычном HTTP-ответе",
    description:
      "Был обнаружен заголовок HTTP Strict Transport Security (HSTS), но заголовки HSTS игнорируются в обычных (не HTTPS) ответах. ",
    cvssScore: 0,
    riskLevel: "Информационный",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N",
    recommendation:
      "Просмотрите конфигурацию этого элемента управления. Убедитесь, что ваш веб-сервер, сервер приложений, балансировщик нагрузки и т. д. настроены на установку Strict-Transport-Security для ответов HTTPS.",
  },
  {
    zapPluginId: "10035-5",
    name: "Strict-Transport-Security: отсутствует параметр Max-Age (не соответствует спецификации)",
    description:
      "Был обнаружен заголовок HTTP Strict Transport Security (HSTS), но в нём отсутствует директива max-age (или в директиве отсутствует значение).",
    cvssScore: 0,
    riskLevel: "Низкий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N/E:U",
    recommendation:
      "Просмотрите конфигурацию этого элемента управления. Убедитесь, что ваш веб-сервер, сервер приложений, балансировщик нагрузки и т. д. настроены на установку Strict-Transport-Security с соответствующим значением max-age.",
  },
  {
    zapPluginId: "10035-6",
    name: "Strict-Transport-Security, определяемая с помощью META (не соответствует спецификации)",
    description:
      "Был обнаружен метатег HTTP Strict Transport Security (HSTS). Определение HTTP Strict Transport Security (HSTS) с помощью метатега явно не поддерживается спецификацией (RFC 6797).",
    cvssScore: 0,
    riskLevel: "Низкий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N/E:U",
    recommendation:
      "Не пытайтесь установить HTTP Strict Transport Security (HSTS) с помощью тега META.",
  },
  {
    zapPluginId: "10035-7",
    name: "Max-Age в заголовке Strict-Transport-Security некорректен (не соответствует спецификации)",
    description:
      "Был обнаружен заголовок HTTP Strict Transport Security (HSTS), но он содержит кавычки перед директивой max-age (значение max-age может быть заключено в кавычки, но сама директива — нет).",
    cvssScore: 0,
    riskLevel: "Низкий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N/E:U",
    recommendation:
      "Просмотрите конфигурацию этого элемента управления. Убедитесь, что ваш веб-сервер, сервер приложений, балансировщик нагрузки и т. д. настроены на установку Strict-Transport-Security в соответствующем формате.",
  },
  {
    zapPluginId: "10035-8",
    name: "Strict-Transport-Security, некорректный контент (не соответствует спецификации)",
    description:
      "Был обнаружен заголовок HTTP Strict Transport Security (HSTS), но он содержит содержимое, которое не ожидалось (возможно, фигурные кавычки). Ожидается, что содержимое будет состоять из печатных символов ASCII.",
    cvssScore: 0,
    riskLevel: "Низкий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N/E:U",
    recommendation:
      "Просмотрите конфигурацию этого элемента управления. Убедитесь, что ваш веб-сервер, сервер приложений, балансировщик нагрузки и т. д. настроены на установку Strict-Transport-Security с соответствующим содержимым.",
  },
  {
    zapPluginId: "10036",
    name: "	HTTP Server Response Header",
    description:
      "Сервер веб-приложений предоставляет доступ к приложению, которое он использует в качестве веб-сервера, через заголовок HTTP-ответа «Server». Доступ к такой информации может помочь злоумышленникам выявить другие уязвимости, которым подвержен ваш сервер веб-приложений. ",
    cvssScore: 0,
    riskLevel: "Низкий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N/E:U",
    recommendation:
      "Настроить веб-сервер на удаление или обобщение информации в HTTP-заголовках (Server, X-Powered-By и др.)",
  },
  {
    zapPluginId: "10036-1",
    name: "Сервер выдаёт информацию о своём веб-сервере в поле заголовка HTTP-ответа «Server»",
    description:
      "Сервер веб-приложений предоставляет доступ к приложению, которое он использует в качестве веб-сервера, через заголовок HTTP-ответа «Server». Доступ к такой информации может помочь злоумышленникам выявить другие уязвимости, которым подвержен ваш сервер веб-приложений. ",
    cvssScore: 0,
    riskLevel: "Информационный",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N",
    recommendation:
      "Убедитесь, что ваш веб-сервер, сервер приложений, балансировщик нагрузки и т. д. настроены на удаление заголовка «Сервер» или предоставление общих сведений.",
  },
  {
    zapPluginId: "10036-2",
    name: "Сервер выдаёт информацию о версии в поле заголовка HTTP-ответа «Server»",
    description:
      "Сервер веб-приложений передаёт информацию о версии через заголовок HTTP-ответа «Сервер». Доступ к такой информации может помочь злоумышленникам выявить другие уязвимости вашего сервера веб-приложений.",
    cvssScore: 0,
    riskLevel: "Низкий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N/E:U",
    recommendation:
      "Убедитесь, что ваш веб-сервер, сервер приложений, балансировщик нагрузки и т. д. настроены на удаление заголовка «Сервер» или предоставление общих сведений.",
  },
  {
    zapPluginId: "10037",
    name: "Сервер предоставляет информацию через поле (поля) заголовка HTTP-ответа «X-Powered-By»",
    description:
      "Сервер веб-приложений/приложений-серверов передаёт информацию через один или несколько заголовков HTTP-ответа «X-Powered-By».",
    cvssScore: 0,
    riskLevel: "Низкий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N/E:U",
    recommendation:
      "Убедитесь, что ваш веб-сервер, сервер приложений, балансировщик нагрузки и т. д. настроены на подавление заголовков X-Powered-By.",
  },
  {
    zapPluginId: "10038-1",
    name: "Content Security Policy (CSP) Header Not Set",
    description:
      "Политика безопасности контента (CSP) — это дополнительный уровень защиты, который помогает обнаруживать и предотвращать определённые типы атак, в том числе межсайтовый скриптинг (XSS) и атаки с внедрением данных. ",
    cvssScore: 0,
    riskLevel: "Средний",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Убедитесь, что ваш веб-сервер, сервер приложений, балансировщик нагрузки и т. д. настроены на установку заголовка Content-Security-Policy.",
  },
  {
    zapPluginId: "10038-2",
    name: "Найден заголовок устаревшей политики безопасности контента (CSP)",
    description:
      "Ответ содержал заголовок Content-Security-Policy-Report-Only, что может указывать на незавершенную реализацию или ошибку при переходе с предварительной версии на рабочую и т.д. ",
    cvssScore: 0,
    riskLevel: "Информационный",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Убедитесь, что ваш веб-сервер, сервер приложений, балансировщик нагрузки и т. д. настроены на установку заголовка Content-Security-Policy.",
  },
  {
    zapPluginId: "10038-3",
    name: "Отчет о политике безопасности контента (CSP) - Найден только заголовок",
    description:
      "Заголовки «X-Content-Security-Policy» и «X-WebKit-CSP» больше не рекомендуются. ",
    cvssScore: 0,
    riskLevel: "Информационный",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Убедитесь, что ваш веб-сервер, сервер приложений, балансировщик нагрузки и т. д. настроены на установку заголовка Content-Security-Policy.",
  },
  {
    zapPluginId: "10039",
    name: "Утечка информации о заголовке X-Backend-Server",
    description:
      "Сервер выдаёт информацию, относящуюся к внутренним системам (например, имена хостов или IP-адреса). Вооружившись этой информацией, злоумышленник может атаковать другие системы или атаковать их напрямую/более эффективно ",
    cvssScore: 0,
    riskLevel: "Низкий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N/E:U",
    recommendation:
      "Убедитесь, что ваш веб-сервер, сервер приложений, балансировщик нагрузки и т. д. настроены на подавление заголовков X-Backend-Server.",
  },
  {
    zapPluginId: "10040",
    name: "Secure Pages Include Mixed Content",
    description:
      "Страница содержит смешанный контент, то есть контент, доступный по протоколу HTTP, а не HTTPS.",
    cvssScore: 0,
    riskLevel: "Низкий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N/E:U",
    recommendation:
      "Страница, доступная по протоколу SSL / TLS, должна полностью состоять из содержимого, которое передается по протоколу SSL / TLS. Страница не должна содержать никакого содержимого, которое передается по незашифрованному HTTP. Сюда входит контент со сторонних сайтов.",
  },
  {
    zapPluginId: "10041",
    name: "Небезопасный переход с HTTP на HTTPS в форме Post",
    description:
      "Эта проверка ищет небезопасные HTTP-страницы, на которых размещены HTTPS-формы. Проблема в том, что небезопасную HTTP-страницу можно легко перехватить с помощью MITM, а безопасную HTTPS-форму можно заменить или подделать.",
    cvssScore: 0,
    riskLevel: "Средний",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Используйте HTTPS для целевых страниц, на которых размещены безопасные формы.",
  },
  {
    zapPluginId: "10042",
    name: "Небезопасный переход с HTTPS на HTTP в форме Post",
    description:
      "Эта проверка выявляет защищённые страницы HTTPS, на которых размещены незащищённые формы HTTP. Проблема в том, что защищённая страница переходит на незащищённую, когда данные загружаются через форму. ",
    cvssScore: 0,
    riskLevel: "Средний",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Убедитесь, что конфиденциальные данные передаются только по защищенным каналам HTTPS.",
  },
  {
    zapPluginId: "10043",
    name: "Управляемое пользователем событие JavaScript (XSS)",
    description:
      "Эта проверка рассматривает вводимые пользователем данные в параметрах строки запроса и POST-данных, чтобы определить, где могут контролироваться определённые значения атрибутов HTML.",
    cvssScore: 0,
    riskLevel: "Информационный",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Проверяйте все вводимые данные и очищайте их перед записью в любой Javascript-код на* событиях.",
  },
  {
    zapPluginId: "10044-1",
    name: "Обнаружено большое перенаправление (Потенциальная утечка конфиденциальной информации)",
    description:
      "Сервер ответил перенаправлением, которое, по-видимому, обеспечивает большой объем данных.",
    cvssScore: 0,
    riskLevel: "Низкий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N/E:U",
    recommendation:
      "Убедитесь, что конфиденциальная информация не попадает в ответ на перенаправление. В ответах на перенаправление почти не должно быть контента.",
  },
  {
    zapPluginId: "10044-2",
    name: "Обнаружено большое перенаправление (Потенциальная утечка конфиденциальной информации)",
    description:
      "Сервер ответил перенаправлением, которое, по-видимому, обеспечивает большой объем данных.",
    cvssScore: 0,
    riskLevel: "Низкий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N/E:U",
    recommendation:
      "Убедитесь, что конфиденциальная информация не попадает в ответ на перенаправление. В ответах на перенаправление почти не должно быть контента.",
  },
  {
    zapPluginId: "10045-1",
    name: "Раскрытие исходного кода - /WEB-INF папка",
    description:
      "Исходный код Java был раскрыт веб-сервером в файлах классов Java в папке WEB-INF.",
    cvssScore: 0,
    riskLevel: "Высокий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Веб-сервер должен быть настроен таким образом, чтобы не предоставлять доступ к папке /WEB-INF или ее содержимому веб-браузерам, поскольку она содержит конфиденциальную информацию, такую как скомпилированный исходный код Java и файлы свойств, которые могут содержать учетные данные.",
  },
  {
    zapPluginId: "10045-2",
    name: "Раскрытие файла свойств - /WEB-INF папка",
    description:
      "Класс Java в папке /WEB-INF указывает на наличие файла свойств. Файлы свойств не предназначены для публичного доступа и обычно содержат информацию о конфигурации, учётные данные приложения или криптографические ключи.",
    cvssScore: 0,
    riskLevel: "Высокий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Веб-сервер должен быть настроен так, чтобы не предоставлять папку /WEB-INF или её содержимое веб-браузерам. Также можно удалить папку /WEB-INF.",
  },
  {
    zapPluginId: "10046",
    name: "Небезопасный компонент",
    description:
      "Судя по результатам пассивного анализа ответа, небезопасный компонент {0} {1}, по-видимому, используется. Наивысший рейтинг CVSS для этой версии продукта составляет {2}. Всего было отмечено {3} уязвимости. В некоторых дистрибутивах Linux, таких как Red Hat, при «обратной поддержке» исправлений безопасности сохраняются старые номера версий. Такие случаи отмечаются как «ложные срабатывания», но их следует проверять вручную.",
    cvssScore: 0,
    riskLevel: "Информационный",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:H/SI:N/SA:N",
    recommendation:
      "Устарело в 2020-02-07. Заменено правилом выхода на пенсию, которое активно поддерживается.",
  },
  {
    zapPluginId: "10047",
    name: "HTTPS-контент, доступный по протоколу HTTP",
    description:
      "Контент, к которому изначально был доступ через HTTPS (то есть с использованием шифрования SSL/TLS), также доступен через HTTP (без шифрования).",
    cvssScore: 0,
    riskLevel: "Низкий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N/E:U",
    recommendation:
      "Убедитесь, что ваш веб-сервер, сервер приложений, балансировщик нагрузки и т. д. настроены на обслуживание такого контента только по протоколу HTTPS. Рассмотрите возможность внедрения строгой транспортной безопасности HTTP.",
  },
  {
    zapPluginId: "10048-1",
    name: "Удаленное выполнение кода - Shell Shock",
    description:
      "На сервере работает версия оболочки Bash, которая позволяет удалённым злоумышленникам выполнять произвольный код.",
    cvssScore: 0,
    riskLevel: "Высокий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    recommendation: "Обновите Bash на сервере до последней версии.",
  },
  {
    zapPluginId: "10048-2",
    name: "Удаленное выполнение кода - Shell Shock",
    description:
      "На сервере работает версия оболочки Bash, которая позволяет удалённым злоумышленникам выполнять произвольный код.",
    cvssScore: 0,
    riskLevel: "Высокий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    recommendation: "Обновите Bash на сервере до последней версии.",
  },
  {
    zapPluginId: "10049-1",
    name: "Контент, не подлежащий хранению",
    description:
      "Содержимое ответа не сохраняется в кэширующих компонентах, таких как прокси-серверы. Если ответ не содержит конфиденциальную, личную или пользовательскую информацию, его можно сохранить и кэшировать для повышения производительности.",
    cvssScore: 0,
    riskLevel: "Информационный",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Содержимое может быть помечено как пригодное для хранения, если выполняются следующие условия: метод запроса должен быть распознан кэшем и определен как пригодный для хранения («GET», «HEAD» и «POST» в настоящее время определены как пригодные для хранения) код состояния ответа должен быть распознан кэшем (обычно распознаются классы ответов 1XX, 2XX, 3XX, 4XX или 5XX) Директива кэша 'no-store' не должна отображаться в полях заголовка запроса или ответа Для кэширования 'shared' кэшами, такими как кэши 'proxy', директива ответа 'private' не должна отображаться в ответе Для кэширования 'shared' кэшами, такими как кэши 'proxy', поле заголовка 'Authorization' не должно отображаться в запросе, если только ответ явно не разрешает это (используя одну из директив ответа для управления кэшем 'must-revalidate', 'public' или 's-maxage').",
  },
  {
    zapPluginId: "10049-2",
    name: "Сохраняемый, но не кэшируемый контент",
    description:
      "Содержимое ответа сохраняется в кэширующих компонентах, таких как прокси-серверы, но не будет извлекаться напрямую из кэша без проверки вышестоящего запроса в ответ на аналогичные запросы других пользователей.",
    cvssScore: 0,
    riskLevel: "Информационный",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Информационная уязвимость не представляет непосредственной угрозы, но может раскрывать данные, полезные для потенциального атакующего. Рекомендуется скрыть лишнюю техническую информацию (заголовки сервера, сообщения об ошибках, конфигурационные файлы), ограничить доступ к служебным директориям и установить безопасные флаги для cookie. Следует регулярно проводить аудит конфигураций и устранять избыточную информацию в ответах сервера.",
  },
  {
    zapPluginId: "10049-3",
    name: "Сохраняемый и кэшируемый контент",
    description:
      "Содержимое ответа сохраняется в кэширующих компонентах, таких как прокси-серверы, и может быть получено непосредственно из кэша, а не с исходного сервера, кэширующими серверами в ответ на аналогичные запросы других пользователей. Если данные ответа являются конфиденциальными, персональными или относящимися к конкретному пользователю, это может привести к утечке конфиденциальной информации.",
    cvssScore: 0,
    riskLevel: "Информационный",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Убедитесь, что ответ не содержит конфиденциальную, личную или пользовательскую информацию. Если это так, рассмотрите возможность использования следующих заголовков HTTP-ответа для ограничения или предотвращения сохранения и извлечения содержимого из кэша другим пользователем: Cache-Control: no-cache, no-store, must-revalidate, private Pragma: no-cache Expires: 0 Эта конфигурация указывает кэширующим серверам, совместимым с HTTP 1.0 и HTTP 1.1, не сохранять ответ и не извлекать ответ (без проверки) из кэша в ответ на аналогичный запрос.",
  },
  {
    zapPluginId: "10050-1",
    name: "Извлечено из кэша",
    description:
      "Контент был получен из общего кэша. Если данные ответа являются конфиденциальными, персональными или относящимися к конкретному пользователю, это может привести к утечке конфиденциальной информации. В некоторых случаях это может даже привести к тому, что пользователь получит полный контроль над сеансом другого пользователя, в зависимости от конфигурации компонентов кэширования, используемых в его среде.",
    cvssScore: 0,
    riskLevel: "Информационный",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Убедитесь, что ответ не содержит конфиденциальную, личную или пользовательскую информацию. Если это так, рассмотрите возможность использования следующих заголовков HTTP-ответа для ограничения или предотвращения сохранения и извлечения содержимого из кэша другим пользователем: Cache-Control: no-cache, no-store, must-revalidate, private Pragma: no-cache Expires: 0 Эта конфигурация указывает кэширующим серверам, совместимым с HTTP 1.0 и HTTP 1.1, не сохранять ответ и не извлекать ответ (без проверки) из кэша в ответ на аналогичный запрос.",
  },
  {
    zapPluginId: "10050-2",
    name: "Извлечено из кэша",
    description:
      "Контент был получен из общего кэша. Если данные ответа являются конфиденциальными, персональными или относящимися к конкретному пользователю, это может привести к утечке конфиденциальной информации. В некоторых случаях это может даже привести к тому, что пользователь получит полный контроль над сеансом другого пользователя, в зависимости от конфигурации компонентов кэширования, используемых в его среде.",
    cvssScore: 0,
    riskLevel: "Информационный",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Убедитесь, что ответ не содержит конфиденциальную, личную или пользовательскую информацию. Если это так, рассмотрите возможность использования следующих заголовков HTTP-ответа для ограничения или предотвращения сохранения и извлечения содержимого из кэша другим пользователем: Cache-Control: no-cache, no-store, must-revalidate, private Pragma: no-cache Expires: 0 Эта конфигурация указывает кэширующим серверам, совместимым с HTTP 1.0 и HTTP 1.1, не сохранять ответ и не извлекать ответ (без проверки) из кэша в ответ на аналогичный запрос.",
  },
  {
    zapPluginId: "10051",
    name: "Путаница в относительном пути",
    description:
      "Веб-сервер настроен на выдачу ответов на неоднозначные URL-адреса таким образом, что это может привести к путанице в отношении правильного «относительного пути» для URL-адреса. Ресурсы (CSS, изображения и т. д.) также указываются в ответе страницы с использованием относительных, а не абсолютных URL-адресов.",
    cvssScore: 0,
    riskLevel: "Средний",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Веб-серверы и фреймворки должны быть обновлены и настроены таким образом, чтобы не выдавать ответы на неоднозначные URL-адреса таким образом, чтобы относительный путь таких URL-адресов мог быть неверно интерпретирован компонентами как на стороне клиента, так и на стороне сервера. В рамках приложения правильное использование HTML-тега '<base>' в HTTP-ответе позволит однозначно указать базовый URL-адрес для всех относительных URL-адресов в документе. Используйте заголовок HTTP-ответа 'Content-Type', чтобы злоумышленнику было сложнее заставить веб-браузер неправильно интерпретировать тип содержимого ответа. Используйте заголовок HTTP-ответа 'X-Content-Type-Options: nosniff', чтобы веб-браузер не «считывал» тип содержимого ответа. Используйте современный DOCTYPE, например '<!doctype html>', чтобы предотвратить рендеринг страницы в веб-браузере в 'режиме совместимости', так как это приводит к игнорированию веб-браузером типа контента. Укажите заголовок HTTP-ответа 'X-Frame-Options', чтобы предотвратить включение 'режима совместимости' в веб-браузере с помощью атак с использованием фреймов.",
  },
  {
    zapPluginId: "10052",
    name: "X-ChromeLogger-Данные (XCOLD) утечка информации в заголовке",
    description:
      "Сервер передаёт информацию через заголовок ответа X-ChromeLogger-Data (или X-ChromePhp-Data). Разработчик может изменять содержимое таких заголовков, однако нередко в них можно найти: расположение файловой системы сервера, объявления виртуальных хостов и т. д.",
    cvssScore: 0,
    riskLevel: "Средний",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Отключите эту функцию в рабочей среде, если она может привести к утечке информации, которой может воспользоваться злоумышленник. В качестве альтернативы убедитесь, что использование этой функции привязано к строгой проверке авторизации и доступно только администраторам или сотрудникам службы поддержки для устранения неполадок, а не обычным пользователям.",
  },
  {
    zapPluginId: "10053",
    name: "X-ChromeLogger-Данные (XCOLD) утечка информации в заголовке",
    description:
      "Фильтр байтовых диапазонов в более ранних версиях HTTP-сервера Apache позволяет удалённым злоумышленникам вызвать отказ в обслуживании (перегрузку памяти и процессора) с помощью заголовка запроса Range, который определяет несколько перекрывающихся диапазонов. Эта уязвимость была использована в реальных условиях в августе 2011 года.",
    cvssScore: 0,
    riskLevel: "Средний",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N",
    recommendation:
      "Устарело 2020-06-13. Получено слишком много ложноположительных результатов, и это больше не актуально.",
  },
  {
    zapPluginId: "10054-1",
    name: "Cookie without SameSite Attribute",
    description:
      "Файл cookie был создан без атрибута SameSite, что означает, что файл cookie может быть отправлен в результате «межсайтового» запроса. Атрибут SameSite является эффективной мерой противодействия подделке межсайтовых запросов, включению межсайтовых скриптов и атакам по времени.",
    cvssScore: 0,
    riskLevel: "Низкий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N/E:U",
    recommendation:
      "Убедитесь, что для всех файлов cookie установлен атрибут SameSite со значением «lax» или, в идеале, «strict».",
  },
  {
    zapPluginId: "10054-2",
    name: "Файл cookie с атрибутом SameSite 'None'",
    description:
      "Файл cookie был создан без атрибута SameSite, что означает, что файл cookie может быть отправлен в результате «межсайтового» запроса. Атрибут SameSite является эффективной мерой противодействия подделке межсайтовых запросов, включению межсайтовых скриптов и атакам по времени.",
    cvssScore: 0,
    riskLevel: "Низкий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N/E:U",
    recommendation:
      "Убедитесь, что для всех файлов cookie установлен атрибут SameSite со значением «lax» или, в идеале, «strict».",
  },
  {
    zapPluginId: "10054-3",
    name: "Файл cookie с недопустимым атрибутом SameSite",
    description:
      "Файл cookie был создан без атрибута SameSite, что означает, что файл cookie может быть отправлен в результате «межсайтового» запроса. Атрибут SameSite является эффективной мерой противодействия подделке межсайтовых запросов, включению межсайтовых скриптов и атакам по времени.",
    cvssScore: 0,
    riskLevel: "Низкий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N/E:U",
    recommendation:
      "Убедитесь, что для всех файлов cookie установлен атрибут SameSite со значением «lax» или, в идеале, «strict».",
  },
  {
    zapPluginId: "10055-1",
    name: "CSP: X-Content-Security-Policy",
    description:
      "Политика безопасности контента (CSP) — это дополнительный уровень безопасности, который помогает обнаруживать и предотвращать определённые типы атак. Включая (но не ограничиваясь этим) межсайтовый скриптинг (XSS) и атаки с внедрением данных. Эти атаки используются для самых разных целей: от кражи данных до порчи сайта или распространения вредоносного ПО. CSP предоставляет набор стандартных HTTP-заголовков, которые позволяют владельцам веб-сайтов объявлять разрешённые источники контента, который браузеры должны загружать на эту страницу.",
    cvssScore: 0,
    riskLevel: "Низкий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N/E:U",
    recommendation:
      "Убедитесь, что ваш веб-сервер, сервер приложений, балансировщик нагрузки и т. д. правильно настроены для установки заголовка Content-Security-Policy.Заголовок X-Content-Security-Policy был найден в этом ответе. Хотя это хороший признак того, что CSP в некоторой степени реализован, политика, указанная в этом заголовке, не была проанализирована ZAP.",
  },
  {
    zapPluginId: "10055-2",
    name: "CSP: X-WebKit-CSP",
    description:
      "Политика безопасности контента (CSP) — это дополнительный уровень безопасности, который помогает обнаруживать и предотвращать определённые типы атак. Включая (но не ограничиваясь этим) межсайтовый скриптинг (XSS) и атаки с внедрением данных. Эти атаки используются для самых разных целей: от кражи данных до порчи сайта или распространения вредоносного ПО. CSP предоставляет набор стандартных HTTP-заголовков, которые позволяют владельцам веб-сайтов объявлять разрешённые источники контента, который браузеры должны загружать на эту страницу.",
    cvssScore: 0,
    riskLevel: "Низкий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N/E:U",
    recommendation:
      "Убедитесь, что ваш веб-сервер, сервер приложений, балансировщик нагрузки и т. д. правильно настроены для установки заголовка Content-Security-Policy.Заголовок X-WebKit-CSP был найден в этом ответе. Хотя это хороший признак того, что CSP в некоторой степени реализован, политика, указанная в этом заголовке, не была проанализирована ZAP. Чтобы обеспечить полную поддержку современными браузерами, убедитесь, что заголовок Content-Security-Policy определен и прикреплен к ответам.",
  },
  {
    zapPluginId: "10055-3",
    name: "CSP: Notices",
    description:
      "Политика безопасности контента (CSP) — это дополнительный уровень безопасности, который помогает обнаруживать и предотвращать определённые типы атак. Включая (но не ограничиваясь этим) межсайтовый скриптинг (XSS) и атаки с внедрением данных. Эти атаки используются для самых разных целей: от кражи данных до порчи сайта или распространения вредоносного ПО. CSP предоставляет набор стандартных HTTP-заголовков, которые позволяют владельцам веб-сайтов объявлять разрешённые источники контента, который браузеры должны загружать на эту страницу.",
    cvssScore: 0,
    riskLevel: "Низкий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N/E:U",
    recommendation:
      "Убедитесь, что ваш веб-сервер, сервер приложений, балансировщик нагрузки и т. д. правильно настроены для установки заголовка Content-Security-Policy.Скорее всего отсутствуют необходимые кавычки и атрибут: «none».",
  },
  {
    zapPluginId: "10055-4",
    name: "CSP: Wildcard Directive",
    description:
      "Политика безопасности контента (CSP) — это дополнительный уровень безопасности, который помогает обнаруживать и предотвращать определённые типы атак. Включая (но не ограничиваясь этим) межсайтовый скриптинг (XSS) и атаки с внедрением данных. Эти атаки используются для самых разных целей: от кражи данных до порчи сайта или распространения вредоносного ПО. CSP предоставляет набор стандартных HTTP-заголовков, которые позволяют владельцам веб-сайтов объявлять разрешённые источники контента, который браузеры должны загружать на эту страницу.",
    cvssScore: 0,
    riskLevel: "Средний",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Убедитесь, что ваш веб-сервер, сервер приложений, балансировщик нагрузки и т. д. правильно настроены для установки заголовка Content-Security-Policy. Следующие директивы либо допускают использование подстановочных знаков в источниках (или предках), либо не определены, либо определены слишком широко: connect-src",
  },
  {
    zapPluginId: "10055-5",
    name: "CSP: script-src unsafe-inline",
    description:
      "Политика безопасности контента (CSP) — это дополнительный уровень безопасности, который помогает обнаруживать и предотвращать определённые типы атак. Включая (но не ограничиваясь этим) межсайтовый скриптинг (XSS) и атаки с внедрением данных. Эти атаки используются для самых разных целей: от кражи данных до порчи сайта или распространения вредоносного ПО. CSP предоставляет набор стандартных HTTP-заголовков, которые позволяют владельцам веб-сайтов объявлять разрешённые источники контента, который браузеры должны загружать на эту страницу.",
    cvssScore: 0,
    riskLevel: "Средний",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Убедитесь, что ваш веб-сервер, сервер приложений, балансировщик нагрузки и т. д. правильно настроены для установки заголовка Content-Security-Policy. script-src включает в себя unsafe-inline.",
  },
  {
    zapPluginId: "10055-6",
    name: "CSP: style-src unsafe-inline",
    description:
      "Политика безопасности контента (CSP) — это дополнительный уровень безопасности, который помогает обнаруживать и предотвращать определённые типы атак. Включая (но не ограничиваясь этим) межсайтовый скриптинг (XSS) и атаки с внедрением данных. Эти атаки используются для самых разных целей: от кражи данных до порчи сайта или распространения вредоносного ПО. CSP предоставляет набор стандартных HTTP-заголовков, которые позволяют владельцам веб-сайтов объявлять разрешённые источники контента, который браузеры должны загружать на эту страницу.",
    cvssScore: 0,
    riskLevel: "Средний",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Убедитесь, что ваш веб-сервер, сервер приложений, балансировщик нагрузки и т. д. правильно настроены для установки заголовка Content-Security-Policy. style-src включает в себя unsafe-inline.",
  },
  {
    zapPluginId: "10055-7",
    name: "CSP: script-src unsafe-hashes",
    description:
      "Политика безопасности контента (CSP) — это дополнительный уровень безопасности, который помогает обнаруживать и предотвращать определённые типы атак. Включая (но не ограничиваясь этим) межсайтовый скриптинг (XSS) и атаки с внедрением данных. Эти атаки используются для самых разных целей: от кражи данных до порчи сайта или распространения вредоносного ПО. CSP предоставляет набор стандартных HTTP-заголовков, которые позволяют владельцам веб-сайтов объявлять разрешённые источники контента, который браузеры должны загружать на эту страницу.",
    cvssScore: 0,
    riskLevel: "Средний",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Убедитесь, что ваш веб-сервер, сервер приложений, балансировщик нагрузки и т. д. правильно настроены для установки заголовка Content-Security-Policy. script-src включает небезопасные хэши, злоумышленник сможет использовать любой код, защищённый такими хэшами.",
  },
  {
    zapPluginId: "10055-8",
    name: "CSP: style-src unsafe-hashes",
    description:
      "Политика безопасности контента (CSP) — это дополнительный уровень безопасности, который помогает обнаруживать и предотвращать определённые типы атак. Включая (но не ограничиваясь этим) межсайтовый скриптинг (XSS) и атаки с внедрением данных. Эти атаки используются для самых разных целей: от кражи данных до порчи сайта или распространения вредоносного ПО. CSP предоставляет набор стандартных HTTP-заголовков, которые позволяют владельцам веб-сайтов объявлять разрешённые источники контента, который браузеры должны загружать на эту страницу.",
    cvssScore: 0,
    riskLevel: "Средний",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Убедитесь, что ваш веб-сервер, сервер приложений, балансировщик нагрузки и т. д. правильно настроены для установки заголовка Content-Security-Policy. style-src включает небезопасные хэши, злоумышленник сможет использовать любой код, защищённый такими хэшами.",
  },
  {
    zapPluginId: "10055-9",
    name: "CSP: Неверно сформированная политика (не в формате ASCII)",
    description:
      "Политика безопасности контента (CSP) — это дополнительный уровень безопасности, который помогает обнаруживать и предотвращать определённые типы атак. Включая (но не ограничиваясь этим) межсайтовый скриптинг (XSS) и атаки с внедрением данных. Эти атаки используются для самых разных целей: от кражи данных до порчи сайта или распространения вредоносного ПО. CSP предоставляет набор стандартных HTTP-заголовков, которые позволяют владельцам веб-сайтов объявлять разрешённые источники контента, который браузеры должны загружать на эту страницу.",
    cvssScore: 0,
    riskLevel: "Средний",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N",
    recommendation:
      "Убедитесь, что ваш веб-сервер, сервер приложений, балансировщик нагрузки и т. д. правильно настроены для установки заголовка Content-Security-Policy.При попытке проанализировать политику был обнаружен символ, не входящий в набор символов ASCII, что сделало её недействительной (дальнейшая оценка не проводилась).",
  },
  {
    zapPluginId: "10055-10",
    name: "CSP: script-src unsafe-eval",
    description:
      "Политика безопасности контента (CSP) — это дополнительный уровень безопасности, который помогает обнаруживать и предотвращать определённые типы атак. Включая (но не ограничиваясь этим) межсайтовый скриптинг (XSS) и атаки с внедрением данных. Эти атаки используются для самых разных целей: от кражи данных до порчи сайта или распространения вредоносного ПО. CSP предоставляет набор стандартных HTTP-заголовков, которые позволяют владельцам веб-сайтов объявлять разрешённые источники контента, который браузеры должны загружать на эту страницу.",
    cvssScore: 0,
    riskLevel: "Средний",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Убедитесь, что ваш веб-сервер, сервер приложений, балансировщик нагрузки и т. д. правильно настроены для установки заголовка Content-Security-Policy.script-src включает unsafe-eval.",
  },
  {
    zapPluginId: "10055-11",
    name: "CSP: Недопустимая Директива Meta Policy",
    description:
      "Политика безопасности контента (CSP) — это дополнительный уровень безопасности, который помогает обнаруживать и предотвращать определённые типы атак. Включая (но не ограничиваясь этим) межсайтовый скриптинг (XSS) и атаки с внедрением данных. Эти атаки используются для самых разных целей: от кражи данных до порчи сайта или распространения вредоносного ПО. CSP предоставляет набор стандартных HTTP-заголовков, которые позволяют владельцам веб-сайтов объявлять разрешённые источники контента, который браузеры должны загружать на эту страницу.",
    cvssScore: 0,
    riskLevel: "Средний",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N",
    recommendation:
      "Убедитесь, что ваш веб-сервер, сервер приложений, балансировщик нагрузки и т. д. правильно настроены для установки заголовка Content-Security-Policy.",
  },
  {
    zapPluginId: "10055-12",
    name: "CSP: Заголовок и Мета",
    description:
      "Политика безопасности контента (CSP) — это дополнительный уровень безопасности, который помогает обнаруживать и предотвращать определённые типы атак. Включая (но не ограничиваясь этим) межсайтовый скриптинг (XSS) и атаки с внедрением данных. Эти атаки используются для самых разных целей: от кражи данных до порчи сайта или распространения вредоносного ПО. CSP предоставляет набор стандартных HTTP-заголовков, которые позволяют владельцам веб-сайтов объявлять разрешённые источники контента, который браузеры должны загружать на эту страницу.",
    cvssScore: 0,
    riskLevel: "Информационный",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N",
    recommendation:
      "Убедитесь, что ваш веб-сервер, сервер приложений, балансировщик нагрузки и т. д. правильно настроены для установки заголовка Content-Security-Policy.",
  },
  {
    zapPluginId: "10055-13",
    name: "CSP: Неспособность определить директиву без запасного варианта",
    description:
      "Политика безопасности контента (CSP) — это дополнительный уровень безопасности, который помогает обнаруживать и предотвращать определённые типы атак. Включая (но не ограничиваясь этим) межсайтовый скриптинг (XSS) и атаки с внедрением данных. Эти атаки используются для самых разных целей: от кражи данных до порчи сайта или распространения вредоносного ПО. CSP предоставляет набор стандартных HTTP-заголовков, которые позволяют владельцам веб-сайтов объявлять разрешённые источники контента, который браузеры должны загружать на эту страницу.",
    cvssScore: 0,
    riskLevel: "Средний",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Убедитесь, что ваш веб-сервер, сервер приложений, балансировщик нагрузки и т. д. правильно настроены для установки заголовка Content-Security-Policy.Директива (или директивы): frame-ancestors входит в число директив, которые не используют default-src в качестве резервной копии.",
  },
  {
    zapPluginId: "10056",
    name: "X-Debug-Token информации о токене",
    description:
      "Ответ содержал заголовок X-Debug-Token или X-Debug-Token-Link. Это указывает на то, что может использоваться профилировщик Symfony, предоставляющий конфиденциальные данные.",
    cvssScore: 0,
    riskLevel: "Низкий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N/E:U",
    recommendation:
      "Ограничьте доступ к профилировщику Symfony с помощью аутентификации/авторизации или ограничьте включение заголовка для определённых клиентов (по IP-адресу и т.д.).",
  },
  {
    zapPluginId: "10057",
    name: "Найден Хэш имени пользователя",
    description:
      "В ответе был обнаружен хэш имени пользователя (admin). Это может указывать на то, что приложение подвержено уязвимости небезопасной прямой ссылки на объект (IDOR). Потребуется ручное тестирование, чтобы выяснить, можно ли использовать это обнаружение.",
    cvssScore: 0,
    riskLevel: "Информационный",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Используйте косвенные ссылки на объекты для каждого пользователя или сеанса (создайте временное сопоставление во время использования). Или убедитесь, что каждое использование прямой ссылки на объект связано с проверкой авторизации, чтобы убедиться, что пользователь имеет доступ к запрашиваемому объекту.",
  },
  {
    zapPluginId: "10058",
    name: "GET для POST",
    description:
      "Запрос, который изначально был отправлен как POST, также был принят как GET. Эта проблема сама по себе не представляет угрозы безопасности, однако она может облегчить проведение других атак.",
    cvssScore: 0,
    riskLevel: "Информационный",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Убедитесь, что принимается только тот запрос, который ожидается.",
  },
  {
    zapPluginId: "10061",
    name: "X-AspNet-Version заголовок ответа",
    description:
      "Сервер передает информацию через поля заголовка HTTP-ответа 'X-AspNet-Version'/ 'X-AspNetMvc-Version'.",
    cvssScore: 0,
    riskLevel: "Низкий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N/E:U",
    recommendation:
      "Настройте сервер так, чтобы он не возвращал эти заголовки. Злоумышленник может использовать эту информацию для использования известных уязвимостей.",
  },
  {
    zapPluginId: "10062",
    name: "PII Disclosure",
    description:
      "Ответ содержит информацию, позволяющую установить личность, такую как номер кредитной карты, номер социального страхования и аналогичные конфиденциальные данные.",
    cvssScore: 0,
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:H/SI:N/SA:N",
    riskLevel: "Высокий",
    recommendation:
      "Проверьте ответ на возможное наличие информации, позволяющей установить личность (PII), убедитесь, что приложение не передаёт конфиденциальные данные.(Обнаружен тип кредитной карты: Visa, Идентификационный номер банка: 471618, Марка: VISA, Категория: ПОКУПКА, Эмитент: U.S. BANK N.A. ND)",
  },
  {
    zapPluginId: "10063-1",
    name: "Заголовок политики разрешений не установлен",
    description:
      "Заголовок политики разрешений — это дополнительный уровень безопасности, который помогает ограничить несанкционированный доступ к веб-ресурсам или использование ими функций браузера/клиента. Эта политика обеспечивает конфиденциальность пользователей, ограничивая или указывая функции браузеров, которые могут использоваться веб-ресурсами.",
    cvssScore: 0,
    riskLevel: "Низкий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N/E:U",
    recommendation:
      "Убедитесь, что ваш веб-сервер, сервер приложений, балансировщик нагрузки и т. д. настроены на установку заголовка Permissions-Policy.",
  },
  {
    zapPluginId: "10063-2",
    name: "Набор заголовков политики устаревших функций",
    description: "Заголовок теперь переименован в Permissions-Policy.",
    cvssScore: 0,
    riskLevel: "Низкий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N/E:U",
    recommendation:
      "Убедитесь, что ваш веб-сервер, сервер приложений, балансировщик нагрузки и т. д. настроены на установку заголовка Permissions-Policy вместо заголовка Feature-Policy.",
  },
  {
    zapPluginId: "10070",
    name: "Использование SAML",
    description: "Применяется SAML (Security Assertion Markup Language) для аутентификации, но отсутствуют или недостаточны механизмы защиты от атак типа replay, signature wrapping или подмены утверждений.",
    cvssScore: 0,
    riskLevel: "Высокий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Применяется SAML (Security Assertion Markup Language) для аутентификации, но отсутствуют или недостаточны механизмы защиты от атак типа replay, signature wrapping или подмены утверждений.",
  },
  {
    zapPluginId: "10094-1",
    name: "ASP.NET раскрытие информации о состоянии просмотра",
    description: "Заголовок теперь переименован в Permissions-Policy.",
    cvssScore: 0,
    riskLevel: "Информационный",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Вручную убедитесь, что ASP.NET ViewState не передаёт конфиденциальную информацию и что данные не могут быть объединены/использованы для эксплуатации других уязвимостей.",
  },
  {
    zapPluginId: "10094-2",
    name: "ASP.NET целостность состояния просмотра",
    description:
      "Приложение не использует код аутентификации сообщений (MAC) для защиты целостности состояния просмотра ASP.NET, которое может быть изменено злоумышленником.",
    cvssScore: 0,
    riskLevel: "Высокий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Убедитесь, что все состояния просмотра ASP.NET защищены от несанкционированного доступа с помощью MAC-адреса, сгенерированного с использованием безопасного алгоритма, и секретного ключа на стороне сервера. Это конфигурация по умолчанию для современной установки ASP.NET, которую можно изменить программно или с помощью конфигурации ASP.NET.",
  },
  {
    zapPluginId: "10094-3",
    name: "Раскрытие информации Base64",
    description:
      "Данные, закодированные в формате Base64, были раскрыты приложением/веб-сервером. Примечание: в целях повышения производительности не все строки в формате Base64 в ответе были проанализированы по отдельности. Аналитик/специалист по безопасности/разработчик (разработчики) должны изучить весь ответ.",
    cvssScore: 0,
    riskLevel: "Информационный",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Вручную убедитесь, что данные Base64 не содержат конфиденциальную информацию и что эти данные нельзя объединить/использовать для эксплуатации других уязвимостей.",
  },
  {
    zapPluginId: "10095",
    name: "Раскрытие файла резервной копии",
    description: "Резервная копия файла была раскрыта веб-сервером.",
    cvssScore: 0,
    riskLevel: "Средний",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Не редактируйте файлы на веб-сервере и убедитесь, что ненужные файлы (включая скрытые) удалены с веб-сервера.",
  },
  {
    zapPluginId: "10096",
    name: "Timestamp Disclosure - Unix",
    description:
      "Временная метка была раскрыта приложением / веб-сервером. - Unix",
    cvssScore: 0,
    riskLevel: "Низкий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N/E:U",
    recommendation:
      "Вручную подтвердите, что данные о времени создания не являются конфиденциальными и что их нельзя объединить, чтобы выявить уязвимые места.",
  },
  {
    zapPluginId: "10097",
    name: "Hash Disclosure - MD4 / MD5",
    description: "Веб-сервер раскрыл хэш. — MD4 / MD5",
    cvssScore: 0,
    riskLevel: "Низкий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N/E:U",
    recommendation:
      "Убедитесь, что хэши, которые используются для защиты учётных данных или других ресурсов, не передаются веб-сервером или базой данных. Как правило, нет необходимости предоставлять доступ к хэшам паролей веб-браузеру.",
  },
  {
    zapPluginId: "10098",
    name: "Неправильная конфигурация между доменами",
    description:
      "Загрузка данных в веб-браузере может быть невозможна из-за неправильной настройки межсайтового обмена ресурсами (CORS) на веб-сервере.",
    cvssScore: 0,
    riskLevel: "Средний",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Убедитесь, что конфиденциальные данные недоступны без аутентификации (например, с помощью белого списка IP-адресов). Настройте HTTP-заголовок «Access-Control-Allow-Origin» на более ограниченный набор доменов или полностью удалите все заголовки CORS, чтобы веб-браузер мог применять политику одного источника (SOP) более строго.",
  },
  {
    zapPluginId: "10099",
    name: "Раскрытие исходного кода - PHP",
    description: "Исходный код приложения был раскрыт веб-сервером. - PHP",
    cvssScore: 0,
    riskLevel: "Средний",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Убедитесь, что исходный код приложения недоступен с помощью альтернативных расширений, и что исходный код не присутствует в других файлах или данных, развернутых на веб-сервере или обслуживаемых веб-сервером.",
  },
  {
    zapPluginId: "10101",
    name: "Проблема с контролем доступа - Неправильная аутентификация",
    description:
      "Недостаточная аутентификация возникает, когда веб-сайт позволяет злоумышленнику получить доступ к конфиденциальному контенту или функциям без надлежащей аутентификации. Хорошим примером веб-сайтов, предоставляющих доступ к конфиденциальным функциям, являются инструменты веб-администрирования. В зависимости от конкретного онлайн-ресурса эти веб-приложения не должны быть доступны напрямую без надлежащей проверки личности пользователя.",
    cvssScore: 0,
    riskLevel: "Высокий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    recommendation:
      "Этап: архитектура и проектирование. Используйте фреймворк или библиотеку аутентификации, например функцию аутентификации OWASP ESAPI.Доступ осуществлен как для пользователя без аутентификации. Запрос распознан как авторизованный: true. Определенное правило доступа к ресурсу гласит, что доступ должен быть: запрещен.",
  },
  {
    zapPluginId: "10102",
    name: "Проблема с контролем доступа - Неправильная авторизация",
    description:
      "Недостаточная авторизация возникает, когда приложение не выполняет надлежащие проверки авторизации, чтобы убедиться, что пользователь выполняет функцию или получает доступ к данным в соответствии с политикой безопасности. Процедуры авторизации должны определять, что разрешено пользователю, сервису или приложению. Когда пользователь проходит аутентификацию на веб-сайте, это не обязательно означает, что он должен иметь полный доступ ко всему контенту и функциям.",
    cvssScore: 0,
    riskLevel: "Высокий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    recommendation:
      "Этапы: архитектура и проектирование; эксплуатация. Очень тщательно управляйте настройкой, администрированием и обработкой привилегий. Явно управляйте доверенными зонами в программном обеспечении. Этап: архитектура и проектирование. Убедитесь, что в конструкцию системы встроена соответствующая сегментация и что сегментация служит для обеспечения и дальнейшего усиления функциональности разделения привилегий. Архитекторы и проектировщики должны полагаться на принцип наименьших привилегий, чтобы решать, когда целесообразно использовать и отбрасывать системные привилегии.",
  },
  {
    zapPluginId: "10103",
    name: "Изображение раскрывает данные о местоположении или конфиденциальности",
    description:
      "Было обнаружено, что изображение содержит встроенную информацию о местоположении, например, GPS-координаты, или другую конфиденциальную информацию, например, серийный номер камеры. В зависимости от контекста изображения на веб-сайте эта информация может раскрывать личные данные пользователей сайта. Например, сайт, который позволяет пользователям загружать фотографии профиля, сделанные дома, может раскрывать адрес дома.",
    cvssScore: 0,
    riskLevel: "Информационный",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N",
    recommendation:
      "Прежде чем разрешить сохранение изображений на сервере и/или их передачу в браузер, удалите встроенную информацию о местоположении из изображения. Это может означать удаление всех данных Exif или только компонента GPS. Также следует удалить другие данные, например серийные номера.",
  },
  {
    zapPluginId: "10104",
    name: "Фаззер пользовательского агента",
    description:
      "Проверяет наличие различий в ответе на основе измененного пользовательского агента (например, для мобильных сайтов, при доступе в качестве поискового робота). Сравнивает код состояния ответа и хэш-код тела ответа с исходным ответом.",
    cvssScore: 0,
    riskLevel: "Информационный",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Информационная уязвимость не представляет непосредственной угрозы, но может раскрывать данные, полезные для потенциального атакующего. Рекомендуется скрыть лишнюю техническую информацию (заголовки сервера, сообщения об ошибках, конфигурационные файлы), ограничить доступ к служебным директориям и установить безопасные флаги для cookie. Следует регулярно проводить аудит конфигураций и устранять избыточную информацию в ответах сервера.",
  },
  {
    zapPluginId: "10105-1",
    name: "Захваченные учетные данные для аутентификации",
    description:
      "Используется небезопасный механизм аутентификации. Это позволяет злоумышленнику получить доступ к имени пользователя и паролю аутентифицированного пользователя. Для базовой аутентификации злоумышленник должен просто отслеживать сетевой трафик до тех пор, пока не будет получен запрос базовой аутентификации, а затем декодировать имя пользователя и пароль в кодировке base64. Для дайджест-аутентификации злоумышленник получает доступ к имени пользователя и, возможно, к паролю, если хэш (включая одноразовый номер) можно успешно взломать или если проводится атака «человек посередине». Злоумышленник осуществляет подслушивание в сети до завершения аутентификации.",
    cvssScore: 0,
    riskLevel: "Средний",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Используйте HTTPS и защищённый механизм аутентификации, который не передаёт имя пользователя или пароль в незашифрованном виде. В частности, избегайте использования механизма базовой аутентификации, поскольку этот простой механизм легко взломать.",
  },
  {
    zapPluginId: "10105-2",
    name: "Слабый метод аутентификации",
    description:
      "При использовании незащищённого соединения применялась базовая или дайджест-аутентификация HTTP. Кто-то, имеющий доступ к сети, может считать учётные данные и использовать их повторно.",
    cvssScore: 0,
    riskLevel: "Средний",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    recommendation:
      "Защитите соединение с помощью HTTPS или используйте более надежный механизм аутентификации.",
  },
  {
    zapPluginId: "10106",
    name: "Сайт только по HTTP",
    description: "Сайт обслуживается только по протоколу HTTP, а не HTTPS.",
    cvssScore: 0,
    riskLevel: "Средний",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Настройте свой веб-сервер или сервер приложений на использование SSL (https).",
  },
  {
    zapPluginId: "10107",
    name: "Httpoxy - Неправильное использование заголовка прокси-сервера",
    description:
      "Сервер инициировал прокси-запрос через прокси-сервер, указанный в заголовке HTTP Proxy запроса. Httpoxy обычно влияет на код, выполняемый в средах CGI или подобных средах.",
    cvssScore: 0,
    riskLevel: "Высокий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    recommendation:
      "Лучшее немедленное решение — блокировать заголовки прокси-запросов как можно раньше, до того, как они попадут в ваше приложение.",
  },
  {
    zapPluginId: "10108",
    name: "Обратное табулирование",
    description:
      "По крайней мере, одна ссылка на этой странице уязвима для обратного перехода по ссылкам, так как она использует атрибут target без ключевых слов «noopener» и «noreferrer» в атрибуте «rel», что позволяет целевой странице получить контроль над этой страницей.",
    cvssScore: 0,
    riskLevel: "Средний",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Не используйте атрибут target, а если вам это необходимо, добавьте атрибут: rel='noopener noreferrer'.",
  },
  {
    zapPluginId: "10109",
    name: "Modern Web Application",
    description:
      "Приложение выглядит как современное веб-приложение. Если вам нужно исследовать его автоматически, то Ajax Spider может оказаться более эффективным, чем стандартный инструмент.",
    cvssScore: 0,
    riskLevel: "Информационный",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Это информационное предупреждение, поэтому никаких изменений не требуется.Были найдены ссылки с целью «_self» — это часто используется современными фреймворками для принудительной полной перезагрузки страницы.",
  },
  {
    zapPluginId: "10110",
    name: "Опасные функции JS",
    description:
      "Похоже, используется опасная функция JavaScript, которая делает сайт уязвимым.",
    cvssScore: 0,
    riskLevel: "Низкий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N/E:U",
    recommendation:
      "Рекомендации по безопасности при использовании этих функций приведены в справочных материалах.",
  },
  {
    zapPluginId: "10111",
    name: "Идентифицирован запрос на аутентификацию",
    description:
      "Данный запрос был идентифицирован как запрос на аутентификацию. Поле «Дополнительная информация» содержит набор строк в формате «ключ=значение», которые идентифицируют все соответствующие поля. Если запрос находится в контексте, в котором для метода аутентификации установлено значение «Автоматическое определение», то это правило изменит аутентификацию в соответствии с идентифицированным запросом.",
    cvssScore: 0,
    riskLevel: "Информационный",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Это скорее информационное предупреждение, чем уязвимость, поэтому исправлять ничего не нужно. Параметр пользователя = имя пользователя, значение пользователя = тестовый параметр-пароль = пароль",
  },
  {
    zapPluginId: "10112",
    name: "Session Management Response Identified",
    description:
      "Указанный ответ был идентифицирован как содержащий токен управления сеансом. Поле «Дополнительная информация» содержит набор токенов заголовков, которые можно использовать в методе управления сеансом на основе заголовков. Если запрос находится в контексте, в котором метод управления сеансом установлен на «Автоматическое определение», то это правило изменит управление сеансом на использование указанных токенов.",
    cvssScore: 0,
    riskLevel: "Информационный",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Это скорее информационное предупреждение, чем уязвимость, поэтому исправлять ничего не нужно. Заголовок:авторизация",
  },
  {
    zapPluginId: "10113",
    name: "Идентифицирован запрос на проверку",
    description:
      "Данный запрос был признан подходящим для проверки подлинности. Если запрос находится в контексте, в котором для стратегии проверки установлено значение «Опрос», но URL-адрес пуст, то это правило заполнит правильные значения.",
    cvssScore: 0,
    riskLevel: "Информационный",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Это скорее информационное предупреждение, чем уязвимость, поэтому исправлять ничего не нужно.",
  },
  {
    zapPluginId: "10115-1",
    name: "Скрипт, запущенный из вредоносного домена (polyfill)",
    description:
      "Страница содержит один или несколько файлов скриптов, загруженных с одного из доменов «polyfill». Они не связаны с библиотекой polyfill.js и, как известно, содержат вредоносный контент.",
    cvssScore: 0,
    riskLevel: "Высокий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    recommendation:
      "Измените все скрипты так, чтобы они использовали известный надежный исходный код на основе их документации.",
  },
  {
    zapPluginId: "10115-2",
    name: "Скрипт, запущенный из вредоносного домена (polyfill)",
    description:
      "Страница содержит один или несколько файлов скриптов, загруженных с одного из доменов «polyfill». Они не связаны с библиотекой polyfill.js и, как известно, содержат вредоносный контент.",
    cvssScore: 0,
    riskLevel: "Высокий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    recommendation:
      "Измените все скрипты так, чтобы они использовали известный надежный исходный код на основе их документации.",
  },
  {
    zapPluginId: "10202",
    name: "Absence of Anti-CSRF Tokens",
    description:
      "В HTML-форме отправки данных не было обнаружено токенов защиты от CSRF. Подделка межсайтового запроса — это атака, которая заключается в принуждении жертвы отправить HTTP-запрос в целевое место назначения без её ведома или согласия, чтобы выполнить действие от её имени. Основная причина — функциональность приложения, использующего предсказуемые действия с URL-адресами/формами. Суть атаки в том, что CSRF использует доверие, которое веб-сайт испытывает к пользователю. В отличие от этого, межсайтовый скриптинг (XSS) использует доверие пользователя к веб-сайту. Как и XSS, атаки CSRF не обязательно являются межсайтовыми, но могут быть таковыми. Подделка межсайтовых запросов также известна как CSRF, XSRF, атака в один клик, использование сеанса, запутавшийся помощник и морской прибой.",
    cvssScore: 0,
    riskLevel: "Средний",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Этап: архитектура и дизайн. Используйте проверенную библиотеку или фреймворк, которые не допускают возникновения этой уязвимости или предоставляют конструкции, позволяющие избежать этой уязвимости. Например, используйте пакеты для защиты от CSRF, такие как OWASP CSRFGuard. Этап: внедрение Убедитесь, что в вашем приложении нет проблем с межсайтовым скриптингом, поскольку большинство средств защиты от CSRF можно обойти с помощью скрипта, контролируемого злоумышленником. Этап: архитектура и проектирование Сгенерируйте уникальный одноразовый номер для каждой формы, поместите его в форму и проверьте одноразовый номер при получении формы. Убедитесь, что одноразовый номер не является предсказуемым (CWE-330). Обратите внимание, что это можно обойти с помощью XSS. Определите особенно опасные операции. Когда пользователь выполняет опасную операцию, отправьте отдельный запрос на подтверждение, чтобы убедиться, что пользователь намеревался выполнить эту операцию. Обратите внимание, что это можно обойти с помощью XSS. Используйте элемент управления ESAPI Session Management. Этот элемент управления включает компонент для защиты от CSRF. Не используйте метод GET для любого запроса, который приводит к изменению состояния. Этап: реализация Проверьте заголовок HTTP Referer, чтобы убедиться, что запрос поступил с ожидаемой страницы. Это может нарушить нормальную работу, поскольку пользователи или прокси-серверы могли отключить отправку реферера из соображений конфиденциальности.",
  },
  {
    zapPluginId: "20012",
    name: "Проверка токенов против CSRF",
    description:
      "Подделка межсайтового запроса - это атака, которая включает в себя принуждение жертвы отправить HTTP-запрос целевому получателю без ее ведома или намерения, чтобы выполнить действие в качестве жертвы. Основная причина - функциональность приложения, использующего предсказуемые действия URL / формы повторяющимся способом. Природа атаки заключается в том, что CSRF использует доверие, которое веб-сайт оказывает пользователю. Напротив, межсайтовый скриптинг (XSS) использует доверие пользователя к веб-сайту. Как и в случае с XSS, атаки CSRF не обязательно являются межсайтовыми, но могут быть и такими. Подделка межсайтовых запросов также известна как CSRF, XSRF, атака в один клик, использование сеанса, «заблудившийся помощник» и «морской серфинг».",
    cvssScore: 0,
    riskLevel: "Средний",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Этап: архитектура и дизайн. Используйте проверенную библиотеку или фреймворк, которые не допускают возникновения этой уязвимости или предоставляют конструкции, позволяющие избежать этой уязвимости. Например, используйте пакеты для защиты от CSRF, такие как OWASP CSRFGuard. Этап: внедрение Убедитесь, что в вашем приложении нет проблем с межсайтовым скриптингом, поскольку большинство средств защиты от CSRF можно обойти с помощью скрипта, контролируемого злоумышленником. Этап: архитектура и проектирование Сгенерируйте уникальный одноразовый номер для каждой формы, поместите его в форму и проверьте одноразовый номер при получении формы. Убедитесь, что одноразовый номер не является предсказуемым (CWE-330). Обратите внимание, что это можно обойти с помощью XSS. Определите особенно опасные операции. Когда пользователь выполняет опасную операцию, отправьте отдельный запрос на подтверждение, чтобы убедиться, что пользователь намеревался выполнить эту операцию. Обратите внимание, что это можно обойти с помощью XSS. Используйте элемент управления ESAPI Session Management. Этот элемент управления включает компонент для защиты от CSRF. Не используйте метод GET для любого запроса, который приводит к изменению состояния. Этап: реализация Проверьте заголовок HTTP Referer, чтобы убедиться, что запрос поступил с ожидаемой страницы. Это может нарушить нормальную работу, поскольку пользователи или прокси-серверы могли отключить отправку реферера из соображений конфиденциальности.",
  },
  {
    zapPluginId: "20014",
    name: "HTTP Parameter Pollution",
    description:
      "Атаки с использованием загрязнённых параметров HTTP (HPP) заключаются во внедрении закодированных разделителей строки запроса в другие существующие параметры. Если веб-приложение не выполняет надлежащую очистку пользовательского ввода, злоумышленник может нарушить логику приложения и выполнить атаки на стороне клиента или на стороне сервера. Одним из последствий атак HPP является то, что злоумышленник может переопределить существующие жёстко заданные параметры HTTP, чтобы изменить поведение приложения, обойти контрольные точки проверки ввода и получить доступ к переменным, которые могут быть недоступны напрямую, и, возможно, использовать их.",
    cvssScore: 0,
    riskLevel: "Информационный",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Правильно очистите пользовательский ввод от разделителей параметров.",
  },
  {
    zapPluginId: "20015",
    name: "Уязвимость Heartbleed OpenSSL",
    description:
      "Реализация TLS в OpenSSL 1.0.1 до версии 1.0.1g некорректно обрабатывает пакеты Heartbeat Extension, что позволяет удалённым злоумышленникам получать конфиденциальную информацию из памяти процесса с помощью специально созданных пакетов, которые вызывают переполнение буфера и могут привести к раскрытию конфиденциальной информации.",
    cvssScore: 0,
    riskLevel: "Высокий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:H/SC:N/SI:N/SA:N",
    recommendation:
      "Обновите до версии OpenSSL 1.0.1g или более поздней. Перевыпустите сертификаты HTTPS. Измените асимметричные закрытые ключи и общие секретные ключи, так как они могли быть скомпрометированы без каких-либо признаков взлома в файлах журналов сервера.",
  },
  {
    zapPluginId: "20016-1",
    name: "Неправильная настройка между доменами - Adobe - Read",
    description:
      "Из-за неправильной настройки веб-сервера возможна подделка межсайтовых запросов на основе Flash/Silverlight.",
    cvssScore: 0,
    riskLevel: "Высокий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Настройте файл crossdomain.xml, чтобы ограничить список доменов, которым разрешено отправлять междоменные запросы на чтение на этот веб-сервер, с помощью <allow-access-from domain='example.com'>. Вы должны предоставлять доступ только к '*' (всем доменам), если вы уверены, что этот сервис не хранит никаких данных с ограниченным доступом, персонализированных или конфиденциальных.",
  },
  {
    zapPluginId: "20016-2",
    name: "Неправильная настройка между доменами - Adobe - Send",
    description:
      "Из-за неправильной настройки веб-сервера возможна подделка межсайтовых запросов на основе Flash/Silverlight.",
    cvssScore: 0,
    riskLevel: "Высокий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Настройте файл crossdomain.xml, чтобы ограничить список доменов, которым разрешено отправлять междоменные запросы на чтение на этот веб-сервер, с помощью <allow-access-from domain='example.com'>. Вы должны предоставлять доступ только к '*' (всем доменам), если вы уверены, что этот сервис не хранит никаких данных с ограниченным доступом, персонализированных или конфиденциальных.",
  },
  {
    zapPluginId: "20016-3",
    name: "Неправильная настройка между доменами - Silverlight",
    description:
      "Из-за неправильной настройки веб-сервера возможна подделка межсайтовых запросов на основе Silverlight.",
    cvssScore: 0,
    riskLevel: "Высокий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Настройте файл clientaccesspolicy.xml, чтобы ограничить список доменов, которым разрешено отправлять междоменные запросы на этот веб-сервер, используя <домен uri='https://example.com' />. Вы должны предоставлять доступ только к '*' (всем доменам), если вы уверены, что этот сервис не хранит никаких данных с ограниченным доступом, персонализированных или конфиденциальных.",
  },
  {
    zapPluginId: "20017",
    name: "Раскрытие исходного кода — CVE-2012-1823",
    description:
      "Некоторые версии PHP, настроенные для работы с использованием CGI, некорректно обрабатывают строки запроса, в которых отсутствует экранированный символ «=», что позволяет выполнять произвольный код. В этом случае на веб-сервере выполнялась команда операционной системы, а результаты возвращались в веб-браузер.",
    cvssScore: 0,
    riskLevel: "Высокий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Обновите PHP до последней стабильной версии или используйте веб-сервер Apache и модуль mod_rewrite для фильтрации вредоносных запросов с помощью директив «RewriteCond» и «RewriteRule».",
  },
  {
    zapPluginId: "20018",
    name: "Удаленное выполнение кода — CVE-2012-1823",
    description:
      "Некоторые версии PHP, настроенные для работы с использованием CGI, некорректно обрабатывают строки запроса, в которых отсутствует экранированный символ «=», что позволяет выполнять произвольный код. В этом случае на веб-сервере выполнялась команда операционной системы, а результаты возвращались в веб-браузер.",
    cvssScore: 0,
    riskLevel: "Высокий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    recommendation:
      "Обновите PHP до последней стабильной версии или используйте веб-сервер Apache и модуль mod_rewrite для фильтрации вредоносных запросов с помощью директив «RewriteCond» и «RewriteRule».",
  },
  {
    zapPluginId: "20019-1",
    name: "Внешнее перенаправление",
    description:
      "Перенаправление URL-адресов — это распространённая функция, используемая веб-сайтами для перенаправления входящего запроса на альтернативный ресурс. Это может быть сделано по разным причинам и часто используется для перемещения ресурсов в структуре каталогов и во избежание нарушения функциональности для пользователей, которые запрашивают ресурс по его предыдущему адресу. Перенаправление URL-адресов также может использоваться для балансировки нагрузки, сокращения URL-адресов или записи исходящих ссылок. ",
    cvssScore: 0,
    riskLevel: "Высокий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Предположим, что все входные данные являются вредоносными. Используйте стратегию проверки входных данных «принимать только то, что известно как хорошее», то есть используйте список допустимых входных данных, которые строго соответствуют спецификациям. Отклоняйте любые входные данные, которые не соответствуют спецификациям, или преобразуйте их в соответствии со спецификациями. Не полагайтесь исключительно на поиск вредоносных или некорректных входных данных (то есть не полагайтесь на список запрещённых данных). Однако списки запрещённых данных могут быть полезны для обнаружения потенциальных атак или определения того, какие входные данные настолько некорректны, что их следует сразу отклонять. При проверке вводимых данных учитывайте все потенциально важные свойства, в том числе длину, тип вводимых данных, полный диапазон допустимых значений, отсутствие или наличие дополнительных вводимых данных, синтаксис, согласованность между связанными полями и соответствие бизнес-правилам. В качестве примера логики бизнес-правил слово «лодка» может быть синтаксически корректным, поскольку содержит только буквенно-цифровые символы, но оно не будет корректным, если вы ожидаете такие цвета, как «красный» или «синий». Используйте разрешённый список URL-адресов или доменов, которые можно использовать для перенаправления. Используйте промежуточную страницу с отказом от ответственности, которая предупреждает пользователя о том, что он покидает ваш сайт. Установите длительный тайм-аут перед перенаправлением или заставьте пользователя перейти по ссылке. Будьте внимательны, чтобы избежать проблем с XSS при создании страницы с отказом от ответственности. Если набор допустимых объектов, таких как имена файлов или URL-адреса, ограничен или известен, создайте сопоставление между набором фиксированных входных значений (например, числовых идентификаторов) и фактическими именами файлов или URL-адресами и отклоняйте все остальные входные данные. ",
  },
  {
    zapPluginId: "20019-2",
    name: "Внешнее перенаправление",
    description:
      "Перенаправление URL-адресов — это распространённая функция, используемая веб-сайтами для перенаправления входящего запроса на альтернативный ресурс. Это может быть сделано по разным причинам и часто используется для перемещения ресурсов в структуре каталогов и во избежание нарушения функциональности для пользователей, которые запрашивают ресурс по его предыдущему адресу. Перенаправление URL-адресов также может использоваться для балансировки нагрузки, сокращения URL-адресов или записи исходящих ссылок. ",
    cvssScore: 0,
    riskLevel: "Высокий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Предположим, что все входные данные являются вредоносными. Используйте стратегию проверки входных данных «принимать только то, что известно как хорошее», то есть используйте список допустимых входных данных, которые строго соответствуют спецификациям. Отклоняйте любые входные данные, которые не соответствуют спецификациям, или преобразуйте их в соответствии со спецификациями. Не полагайтесь исключительно на поиск вредоносных или некорректных входных данных (то есть не полагайтесь на список запрещённых данных). Однако списки запрещённых данных могут быть полезны для обнаружения потенциальных атак или определения того, какие входные данные настолько некорректны, что их следует сразу отклонять. При проверке вводимых данных учитывайте все потенциально важные свойства, в том числе длину, тип вводимых данных, полный диапазон допустимых значений, отсутствие или наличие дополнительных вводимых данных, синтаксис, согласованность между связанными полями и соответствие бизнес-правилам. В качестве примера логики бизнес-правил слово «лодка» может быть синтаксически корректным, поскольку содержит только буквенно-цифровые символы, но оно не будет корректным, если вы ожидаете такие цвета, как «красный» или «синий». Используйте разрешённый список URL-адресов или доменов, которые можно использовать для перенаправления. Используйте промежуточную страницу с отказом от ответственности, которая предупреждает пользователя о том, что он покидает ваш сайт. Установите длительный тайм-аут перед перенаправлением или заставьте пользователя перейти по ссылке. Будьте внимательны, чтобы избежать проблем с XSS при создании страницы с отказом от ответственности. Если набор допустимых объектов, таких как имена файлов или URL-адреса, ограничен или известен, создайте сопоставление между набором фиксированных входных значений (например, числовых идентификаторов) и фактическими именами файлов или URL-адресами и отклоняйте все остальные входные данные. ",
  },
  {
    zapPluginId: "20019-3",
    name: "Внешнее перенаправление",
    description:
      "Перенаправление URL-адресов — это распространённая функция, используемая веб-сайтами для перенаправления входящего запроса на альтернативный ресурс. Это может быть сделано по разным причинам и часто используется для перемещения ресурсов в структуре каталогов и во избежание нарушения функциональности для пользователей, которые запрашивают ресурс по его предыдущему адресу. Перенаправление URL-адресов также может использоваться для балансировки нагрузки, сокращения URL-адресов или записи исходящих ссылок. ",
    cvssScore: 0,
    riskLevel: "Высокий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Предположим, что все входные данные являются вредоносными. Используйте стратегию проверки входных данных «принимать только то, что известно как хорошее», то есть используйте список допустимых входных данных, которые строго соответствуют спецификациям. Отклоняйте любые входные данные, которые не соответствуют спецификациям, или преобразуйте их в соответствии со спецификациями. Не полагайтесь исключительно на поиск вредоносных или некорректных входных данных (то есть не полагайтесь на список запрещённых данных). Однако списки запрещённых данных могут быть полезны для обнаружения потенциальных атак или определения того, какие входные данные настолько некорректны, что их следует сразу отклонять. При проверке вводимых данных учитывайте все потенциально важные свойства, в том числе длину, тип вводимых данных, полный диапазон допустимых значений, отсутствие или наличие дополнительных вводимых данных, синтаксис, согласованность между связанными полями и соответствие бизнес-правилам. В качестве примера логики бизнес-правил слово «лодка» может быть синтаксически корректным, поскольку содержит только буквенно-цифровые символы, но оно не будет корректным, если вы ожидаете такие цвета, как «красный» или «синий». Используйте разрешённый список URL-адресов или доменов, которые можно использовать для перенаправления. Используйте промежуточную страницу с отказом от ответственности, которая предупреждает пользователя о том, что он покидает ваш сайт. Установите длительный тайм-аут перед перенаправлением или заставьте пользователя перейти по ссылке. Будьте внимательны, чтобы избежать проблем с XSS при создании страницы с отказом от ответственности. Если набор допустимых объектов, таких как имена файлов или URL-адреса, ограничен или известен, создайте сопоставление между набором фиксированных входных значений (например, числовых идентификаторов) и фактическими именами файлов или URL-адресами и отклоняйте все остальные входные данные. ",
  },
  {
    zapPluginId: "20019-4",
    name: "Внешнее перенаправление",
    description:
      "Перенаправление URL-адресов — это распространённая функция, используемая веб-сайтами для перенаправления входящего запроса на альтернативный ресурс. Это может быть сделано по разным причинам и часто используется для перемещения ресурсов в структуре каталогов и во избежание нарушения функциональности для пользователей, которые запрашивают ресурс по его предыдущему адресу. Перенаправление URL-адресов также может использоваться для балансировки нагрузки, сокращения URL-адресов или записи исходящих ссылок. ",
    cvssScore: 0,
    riskLevel: "Высокий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Предположим, что все входные данные являются вредоносными. Используйте стратегию проверки входных данных «принимать только то, что известно как хорошее», то есть используйте список допустимых входных данных, которые строго соответствуют спецификациям. Отклоняйте любые входные данные, которые не соответствуют спецификациям, или преобразуйте их в соответствии со спецификациями. Не полагайтесь исключительно на поиск вредоносных или некорректных входных данных (то есть не полагайтесь на список запрещённых данных). Однако списки запрещённых данных могут быть полезны для обнаружения потенциальных атак или определения того, какие входные данные настолько некорректны, что их следует сразу отклонять. При проверке вводимых данных учитывайте все потенциально важные свойства, в том числе длину, тип вводимых данных, полный диапазон допустимых значений, отсутствие или наличие дополнительных вводимых данных, синтаксис, согласованность между связанными полями и соответствие бизнес-правилам. В качестве примера логики бизнес-правил слово «лодка» может быть синтаксически корректным, поскольку содержит только буквенно-цифровые символы, но оно не будет корректным, если вы ожидаете такие цвета, как «красный» или «синий». Используйте разрешённый список URL-адресов или доменов, которые можно использовать для перенаправления. Используйте промежуточную страницу с отказом от ответственности, которая предупреждает пользователя о том, что он покидает ваш сайт. Установите длительный тайм-аут перед перенаправлением или заставьте пользователя перейти по ссылке. Будьте внимательны, чтобы избежать проблем с XSS при создании страницы с отказом от ответственности. Если набор допустимых объектов, таких как имена файлов или URL-адреса, ограничен или известен, создайте сопоставление между набором фиксированных входных значений (например, числовых идентификаторов) и фактическими именами файлов или URL-адресами и отклоняйте все остальные входные данные. ",
  },
  {
    zapPluginId: "30001",
    name: "Переполнение буфера",
    description:
      "Ошибки переполнения буфера характеризуются перезаписью областей памяти фонового веб-процесса, которые не должны были быть изменены намеренно или случайно. Перезапись значений IP (указателя инструкций), BP (базового указателя) и других регистров приводит к возникновению исключений, ошибок сегментации и других ошибок процесса. Обычно эти ошибки приводят к неожиданному завершению работы приложения.",
    cvssScore: 0,
    riskLevel: "Средний",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:P/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N",
    recommendation:
      "Перепишите фоновую программу с использованием правильной проверки возвращаемой длины. Это потребует перекомпиляции исполняемого файла фона. Возможное переполнение буфера. Скрипт закрыл соединение и выдал ошибку 500 «Внутренняя ошибка сервера».",
  },
  {
    zapPluginId: "30002",
    name: "Ошибка форматирования строки",
    description:
      "Ошибка строки формата возникает, когда приложение интерпретирует отправленные данные строки ввода как команду.",
    cvssScore: 0,
    riskLevel: "Средний",
    cvssVector: "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N",
    recommendation:
      "Перепишите фоновую программу, удалив неверные символьные строки. Для этого потребуется перекомпилировать фоновый исполняемый файл. Возможная ошибка в строке формата. Скрипт закрыл соединение на /%s.",
  },
  {
    zapPluginId: "30003",
    name: "Ошибка переполнения целого числа",
    description:
      "Целочисленное переполнение возникает, когда целое число, используемое в скомпилированной программе, выходит за пределы допустимого диапазона и не было должным образом проверено во входном потоке.",
    cvssScore: 0,
    riskLevel: "Средний",
    cvssVector: "CVSS:4.0/AV:N/AC:H/AT:P/PR:N/UI:N/VC:L/VI:L/VA:L/SC:N/SI:N/SA:N",
    recommendation:
      "Чтобы предотвратить переполнение и ошибки деления на 0 (ноль) в приложении, пожалуйста, перепишите серверную программу, проверяя, находятся ли значения обрабатываемых целых чисел в допустимом диапазоне приложения. Для этого потребуется перекомпиляция внутреннего исполняемого файла. Возможное целочисленное переполнение. Код состояния изменился при вводе длинной строки случайных целых чисел.",
  },
  {
    zapPluginId: "40003",
    name: "Инъекция CRLF",
    description:
      "Куки-файлы могут быть установлены с помощью внедрения CRLF. Также можно установить произвольные заголовки HTTP-ответа. Кроме того, при тщательном составлении внедряемого ответа с использованием межсайтового скриптинга может возникнуть уязвимость, связанная с отравлением кэша.",
    cvssScore: 0,
    riskLevel: "Средний",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Внимательно проверьте введенный параметр. Не допускайте внедрения CRLF путем фильтрации CRLF.",
  },
  {
    zapPluginId: "40008",
    name: "Изменение параметров",
    description:
      "Манипуляции с параметрами приводили к отображению страницы с ошибкой или трассировки стека Java. Это указывало на отсутствие обработки исключений и потенциальные области для дальнейшего использования.",
    cvssScore: 0,
    riskLevel: "Средний",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Определите причину ошибки и устраните её. Не доверяйте вводу данных на стороне клиента и обеспечьте тщательную проверку на стороне сервера. Кроме того, правильно обрабатывайте исключения. Используйте общую страницу с ошибкой 500 для внутренних ошибок сервера.",
  },
  {
    zapPluginId: "40009",
    name: "Серверная часть включает в себя",
    description:
      "Некоторые параметры могут приводить к выполнению команд на стороне сервера. Это может привести к подключению к базе данных или выполнению произвольного кода.",
    cvssScore: 0,
    riskLevel: "Высокий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Не доверяйте вводу данных на стороне клиента и обеспечьте тщательную проверку на стороне сервера. Отключите включение на стороне сервера. Чтобы отключить включение на стороне сервера, обратитесь к руководству. Используйте наименьшие привилегии для запуска веб-сервера или сервера приложений. Для Apache отключите следующее: Options Indexes FollowSymLinks Includes AddType application/x-httpd-cgi .cgi AddType text/x-server-parsed-html .html.",
  },
  {
    zapPluginId: "40012",
    name: "Межсайтовый скриптинг (отражен)",
    description:
      "Межсайтовый скриптинг (XSS) — это метод атаки, который заключается в отображении кода, предоставленного злоумышленником, в экземпляре браузера пользователя. Экземпляром браузера может быть стандартный веб-браузер или объект браузера, встроенный в программный продукт, например браузер в WinAmp, программу для чтения RSS-лент или почтовый клиент. Сам код обычно написан на HTML/JavaScript, но может также включать VBScript, ActiveX, Java, Flash или любую другую технологию, поддерживаемую браузером. Когда злоумышленник получает доступ к браузеру пользователя для выполнения своего кода, этот код будет работать в контексте безопасности (или зоне) веб-сайта, на котором он размещён. При таком уровне доступа код может считывать, изменять и передавать любые конфиденциальные данные, доступные браузеру. Пользователь, подвергшийся межсайтовому скриптингу, может столкнуться с захватом своей учётной записи (кражей файлов cookie), перенаправлением браузера в другое место или, возможно, с мошенническим контентом, предоставляемым веб-сайтом, который он посещает. Атаки с использованием межсайтового скриптинга, по сути, нарушают доверительные отношения между пользователем и веб-сайтом. Приложения, использующие экземпляры объектов браузера, которые загружают контент из файловой системы, могут выполнять код в зоне локальной машины, что позволяет скомпрометировать систему.",
    cvssScore: 0,
    riskLevel: "Высокий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Этап: архитектура и дизайн. Используйте проверенную библиотеку или фреймворк, которые не допускают возникновения этой уязвимости или предоставляют конструкции, позволяющие избежать этой уязвимости. Примеры библиотек и фреймворков, которые упрощают создание правильно закодированного вывода, включают библиотеку Microsoft Anti-XSS, модуль OWASP ESAPI Encoding и Apache Wicket. Этапы: реализация; архитектура и проектирование. Подумайте о контексте, в котором будут использоваться ваши данные, и о том, какая кодировка ожидается. Это особенно важно при передаче данных между различными компонентами или при создании вывода, который может содержать несколько кодировок одновременно, например веб-страниц или многокомпонентных почтовых сообщений. Изучите все ожидаемые протоколы связи и представления данных, чтобы определить необходимые стратегии кодирования. Для любых данных, которые будут выводиться на другую веб-страницу, особенно для данных, полученных из внешних источников, используйте соответствующую кодировку для всех небуквенно-цифровых символов. Для получения более подробной информации о необходимых типах кодирования и экранировании обратитесь к шпаргалке по предотвращению XSS. Этап: архитектура и проектирование. Для любых проверок безопасности, выполняемых на стороне клиента, убедитесь, что эти проверки дублируются на стороне сервера, чтобы избежать CWE-602. Злоумышленники могут обойти проверки на стороне клиента, изменив значения после выполнения проверок или изменив клиента так, чтобы полностью исключить проверки на стороне клиента. Затем эти изменённые значения будут отправлены на сервер. Если возможно, используйте структурированные механизмы, которые автоматически обеспечивают разделение данных и кода. Эти механизмы могут автоматически обеспечивать соответствующую обработку кавычек, кодировку и проверку, вместо того чтобы полагаться на то, что разработчик обеспечит эту возможность в каждой точке, где генерируется вывод. Этап: реализация Для каждой создаваемой веб-страницы используйте и указывайте кодировку символов, например ISO-8859-1 или UTF-8. Если кодировка не указана, веб-браузер может выбрать другую кодировку, предполагая, какая кодировка используется на веб-странице. Это может привести к тому, что веб-браузер будет рассматривать определённые последовательности как специальные, открывая клиента для скрытых XSS-атак.",
  },
  {
    zapPluginId: "40013",
    name: "Фиксация сеанса",
    description:
      "Возможна фиксация сеанса. Если эта проблема возникает с URL-адресом для входа в систему (где пользователь проходит аутентификацию в приложении), то злоумышленник может передать жертве URL-адрес вместе с фиксированным идентификатором сеанса, чтобы впоследствии использовать его для идентификации жертвы. Если проблема возникает на странице без входа в систему, злоумышленник может использовать URL-адрес и фиксированный идентификатор сеанса только для отслеживания действий пользователя без аутентификации. Если уязвимость возникает в поле файла cookie или в поле формы (параметр POST), а не в параметре URL (GET), то для установки поля файла cookie в браузере жертвы может потребоваться другая уязвимость, чтобы можно было воспользоваться этой уязвимостью.",
    cvssScore: 0,
    riskLevel: "Высокий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "1) Не позволяйте злоумышленнику получить идентификатор сеанса, применяя строгие идентификаторы сеансов и выделяя идентификаторы сеансов только после успешной аутентификации в приложении. 2) Сервер должен всегда создавать новый идентификатор сеанса после аутентификации, независимо от того, существует ли уже сеанс. 3) Привяжите идентификатор сеанса к комбинации идентифицируемых атрибутов клиента, таких как IP-адрес, сертификат SSL-клиента. 4) При уничтожении сеанса он должен быть уничтожен как на сервере, так и на клиенте. 5) Внедрите механизм выхода из системы, который уничтожит все предыдущие сеансы для клиента. 6) Внедрите абсолютные тайм-ауты сеанса. 7) Переключитесь с реализации идентификатора сеанса на основе URL-адреса на основе файлов cookie или форм, поскольку последние обычно требуют дополнительных уязвимостей, чтобы ими мог воспользоваться злоумышленник.",
  },
  {
    zapPluginId: "40014",
    name: "Межсайтовый скриптинг (постоянный)",
    description:
      "Межсайтовый скриптинг (XSS) — это метод атаки, который заключается в отображении кода, предоставленного злоумышленником, в экземпляре браузера пользователя. Экземпляром браузера может быть стандартный веб-браузер или объект браузера, встроенный в программный продукт, например браузер в WinAmp, программу для чтения RSS-лент или почтовый клиент. Сам код обычно написан на HTML/JavaScript, но может также включать VBScript, ActiveX, Java, Flash или любую другую технологию, поддерживаемую браузером. Когда злоумышленник получает доступ к браузеру пользователя для выполнения своего кода, этот код будет работать в контексте безопасности (или зоне) веб-сайта, на котором он размещён. При таком уровне доступа код может считывать, изменять и передавать любые конфиденциальные данные, доступные браузеру. Пользователь, подвергшийся межсайтовому скриптингу, может столкнуться с захватом своей учётной записи (кражей файлов cookie), перенаправлением браузера в другое место или, возможно, с мошенническим контентом, предоставляемым веб-сайтом, который он посещает. Атаки с использованием межсайтового скриптинга, по сути, нарушают доверительные отношения между пользователем и веб-сайтом. Приложения, использующие экземпляры объектов браузера, которые загружают контент из файловой системы, могут выполнять код в зоне локальной машины, что позволяет скомпрометировать систему.",
    cvssScore: 0,
    riskLevel: "Высокий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Этап: архитектура и дизайн. Используйте проверенную библиотеку или фреймворк, которые не допускают возникновения этой уязвимости или предоставляют конструкции, позволяющие избежать этой уязвимости. Примеры библиотек и фреймворков, которые упрощают создание правильно закодированного вывода, включают библиотеку Microsoft Anti-XSS, модуль OWASP ESAPI Encoding и Apache Wicket. Этапы: реализация; архитектура и проектирование. Подумайте о контексте, в котором будут использоваться ваши данные, и о том, какая кодировка ожидается. Это особенно важно при передаче данных между различными компонентами или при создании вывода, который может содержать несколько кодировок одновременно, например веб-страниц или многокомпонентных почтовых сообщений. Изучите все ожидаемые протоколы связи и представления данных, чтобы определить необходимые стратегии кодирования. Для любых данных, которые будут выводиться на другую веб-страницу, особенно для данных, полученных из внешних источников, используйте соответствующую кодировку для всех небуквенно-цифровых символов. Для получения более подробной информации о необходимых типах кодирования и экранировании обратитесь к шпаргалке по предотвращению XSS. Этап: архитектура и проектирование. Для любых проверок безопасности, выполняемых на стороне клиента, убедитесь, что эти проверки дублируются на стороне сервера, чтобы избежать CWE-602. Злоумышленники могут обойти проверки на стороне клиента, изменив значения после выполнения проверок или изменив клиента так, чтобы полностью исключить проверки на стороне клиента. Затем эти изменённые значения будут отправлены на сервер. Если возможно, используйте структурированные механизмы, которые автоматически обеспечивают разделение данных и кода. Эти механизмы могут автоматически обеспечивать соответствующую обработку кавычек, кодировку и проверку, вместо того чтобы полагаться на то, что разработчик обеспечит эту возможность в каждой точке, где генерируется вывод. Этап: реализация Для каждой создаваемой веб-страницы используйте и указывайте кодировку символов, например ISO-8859-1 или UTF-8. Если кодировка не указана, веб-браузер может выбрать другую кодировку, предполагая, какая кодировка используется на веб-странице. Это может привести к тому, что веб-браузер будет рассматривать определённые последовательности как специальные, открывая клиента для скрытых XSS-атак. ",
  },
  {
    zapPluginId: "40015",
    name: "Внедрение LDAP",
    description:
      "Возможна инжекция LDAP. Злоумышленник может обойти средства аутентификации, просматривать и изменять произвольные данные в каталоге LDAP.",
    cvssScore: 0,
    riskLevel: "Высокий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Проверьте и / или экранируйте все введенные пользователем данные, прежде чем использовать их для создания запроса LDAP. В частности, следующие символы (или комбинации) должны быть запрещены в списке: & | ! < > = ~= >= <= * ( ) , + - ' ;  / НУЛЕВОЙ символ",
  },
  {
    zapPluginId: "40016",
    name: "Межсайтовый скриптинг (постоянный) - Prime",
    description: "-",
    cvssScore: 0,
    riskLevel: "Информационный",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Информационная уязвимость не представляет непосредственной угрозы, но может раскрывать данные, полезные для потенциального атакующего. Рекомендуется скрыть лишнюю техническую информацию (заголовки сервера, сообщения об ошибках, конфигурационные файлы), ограничить доступ к служебным директориям и установить безопасные флаги для cookie. Следует регулярно проводить аудит конфигураций и устранять избыточную информацию в ответах сервера.",
  },
  {
    zapPluginId: "40017",
    name: "Межсайтовый скриптинг (постоянный) - Spider",
    description: "-",
    cvssScore: 0,
    riskLevel: "Информационный",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Информационная уязвимость не представляет непосредственной угрозы, но может раскрывать данные, полезные для потенциального атакующего. Рекомендуется скрыть лишнюю техническую информацию (заголовки сервера, сообщения об ошибках, конфигурационные файлы), ограничить доступ к служебным директориям и установить безопасные флаги для cookie. Следует регулярно проводить аудит конфигураций и устранять избыточную информацию в ответах сервера.",
  },
  {
    zapPluginId: "40018",
    name: "SQL-инъекция",
    description: "Возможна SQL-инъекция.",
    cvssScore: 0,
    riskLevel: "Высокий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    recommendation:
      "Не доверяйте вводу данных на стороне клиента, даже если на стороне клиента выполняется проверка. В целом, проверяйте все данные на стороне сервера. Если приложение использует JDBC, используйте PreparedStatement или CallableStatement с параметрами, передаваемыми с помощью '?' Если приложение использует ASP, используйте командные объекты ADO с строгой проверкой типов и параметризованными запросами. Если можно использовать хранимые процедуры базы данных, используйте их. *Не* объединяйте строки в запросах в хранимой процедуре и не используйте «exec», «exec immediate» или аналогичные функции! Не создавайте динамические SQL-запросы с помощью простого объединения строк. Экранируйте все данные, полученные от клиента. Применяйте «разрешённый список» допустимых символов или «запрещённый список» недопустимых символов во вводимых пользователем данных. Применяйте принцип наименьших привилегий, используя пользователя базы данных с наименьшими привилегиями. В частности, не используйте пользователей базы данных 'sa' или 'db-owner'. Это не устранит SQL-инъекции, но минимизирует их влияние. Предоставьте минимальный доступ к базе данных, необходимый для работы приложения.",
  },
  {
    zapPluginId: "40019",
    name: "SQL - инъекция - MySQL",
    description: "Возможна SQL-инъекция.",
    cvssScore: 0,
    riskLevel: "Высокий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    recommendation:
      "Не доверяйте вводу данных на стороне клиента, даже если на стороне клиента выполняется проверка. В целом, проверяйте все данные на стороне сервера. Если приложение использует JDBC, используйте PreparedStatement или CallableStatement с параметрами, передаваемыми с помощью '?' Если приложение использует ASP, используйте командные объекты ADO с строгой проверкой типов и параметризованными запросами. Если можно использовать хранимые процедуры базы данных, используйте их. *Не* объединяйте строки в запросах в хранимой процедуре и не используйте «exec», «exec immediate» или аналогичные функции! Не создавайте динамические SQL-запросы с помощью простого объединения строк. Экранируйте все данные, полученные от клиента. Применяйте «разрешённый список» допустимых символов или «запрещённый список» недопустимых символов во вводимых пользователем данных. Применяйте принцип наименьших привилегий, используя пользователя базы данных с наименьшими привилегиями. В частности, не используйте пользователей базы данных 'sa' или 'db-owner'. Это не устранит SQL-инъекции, но минимизирует их влияние. Предоставьте минимальный доступ к базе данных, необходимый для работы приложения.",
  },
  {
    zapPluginId: "40020",
    name: "SQL-инъекция - Hypersonic SQL",
    description: "Возможна SQL-инъекция.",
    cvssScore: 0,
    riskLevel: "Высокий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    recommendation:
      "Не доверяйте вводу данных на стороне клиента, даже если на стороне клиента выполняется проверка. В целом, проверяйте все данные на стороне сервера. Если приложение использует JDBC, используйте PreparedStatement или CallableStatement с параметрами, передаваемыми с помощью '?' Если приложение использует ASP, используйте командные объекты ADO с строгой проверкой типов и параметризованными запросами. Если можно использовать хранимые процедуры базы данных, используйте их. *Не* объединяйте строки в запросах в хранимой процедуре и не используйте «exec», «exec immediate» или аналогичные функции! Не создавайте динамические SQL-запросы с помощью простого объединения строк. Экранируйте все данные, полученные от клиента. Применяйте «разрешённый список» допустимых символов или «запрещённый список» недопустимых символов во вводимых пользователем данных. Применяйте принцип наименьших привилегий, используя пользователя базы данных с наименьшими привилегиями. В частности, не используйте пользователей базы данных 'sa' или 'db-owner'. Это не устранит SQL-инъекции, но минимизирует их влияние. Предоставьте минимальный доступ к базе данных, необходимый для работы приложения.",
  },
  {
    zapPluginId: "40021",
    name: "SQL-инъекция - Oracle",
    description: "Возможна SQL-инъекция.",
    cvssScore: 0,
    riskLevel: "Высокий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    recommendation:
      "Не доверяйте вводу данных на стороне клиента, даже если на стороне клиента выполняется проверка. В целом, проверяйте все данные на стороне сервера. Если приложение использует JDBC, используйте PreparedStatement или CallableStatement с параметрами, передаваемыми с помощью '?' Если приложение использует ASP, используйте командные объекты ADO с строгой проверкой типов и параметризованными запросами. Если можно использовать хранимые процедуры базы данных, используйте их. *Не* объединяйте строки в запросах в хранимой процедуре и не используйте «exec», «exec immediate» или аналогичные функции! Не создавайте динамические SQL-запросы с помощью простого объединения строк. Экранируйте все данные, полученные от клиента. Применяйте «разрешённый список» допустимых символов или «запрещённый список» недопустимых символов во вводимых пользователем данных. Применяйте принцип наименьших привилегий, используя пользователя базы данных с наименьшими привилегиями. В частности, не используйте пользователей базы данных 'sa' или 'db-owner'. Это не устранит SQL-инъекции, но минимизирует их влияние. Предоставьте минимальный доступ к базе данных, необходимый для работы приложения.",
  },
  {
    zapPluginId: "40022",
    name: "SQL-инъекция - PostgreSQL",
    description: "Возможна SQL-инъекция.",
    cvssScore: 0,
    riskLevel: "Высокий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    recommendation:
      "Не доверяйте вводу данных на стороне клиента, даже если на стороне клиента выполняется проверка. В целом, проверяйте все данные на стороне сервера. Если приложение использует JDBC, используйте PreparedStatement или CallableStatement с параметрами, передаваемыми с помощью '?' Если приложение использует ASP, используйте командные объекты ADO с строгой проверкой типов и параметризованными запросами. Если можно использовать хранимые процедуры базы данных, используйте их. *Не* объединяйте строки в запросах в хранимой процедуре и не используйте «exec», «exec immediate» или аналогичные функции! Не создавайте динамические SQL-запросы с помощью простого объединения строк. Экранируйте все данные, полученные от клиента. Применяйте «разрешённый список» допустимых символов или «запрещённый список» недопустимых символов во вводимых пользователем данных. Применяйте принцип наименьших привилегий, используя пользователя базы данных с наименьшими привилегиями. В частности, не используйте пользователей базы данных 'sa' или 'db-owner'. Это не устранит SQL-инъекции, но минимизирует их влияние. Предоставьте минимальный доступ к базе данных, необходимый для работы приложения.",
  },
  {
    zapPluginId: "40023",
    name: "Возможное перечисление имени пользователя",
    description:
      "Возможно, удастся перебрать имена пользователей на основе различий в HTTP-ответах при вводе правильных и неправильных имён пользователей. Это значительно повысит вероятность успешной атаки методом перебора паролей на систему. Обратите внимание, что ложные срабатывания иногда можно свести к минимуму, увеличив параметр «Сила атаки» в ZAP. Пожалуйста, вручную проверьте поле «Дополнительная информация», чтобы убедиться, что проблема действительно существует.",
    cvssScore: 0,
    riskLevel: "Информационный",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N",
    recommendation:
      "Не раскрывайте информацию о том, является ли имя пользователя действительным или недействительным. В частности, при неудачных попытках входа в систему не делайте различий между недействительным именем пользователя и недействительным паролем в сообщении об ошибке, заголовке страницы, содержимом страницы, HTTP-заголовках или логике перенаправления.",
  },
  {
    zapPluginId: "40024",
    name: "SQL- инъекция - SQLite",
    description: "Возможна SQL-инъекция.",
    cvssScore: 0,
    riskLevel: "Высокий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    recommendation:
      "Не доверяйте вводу данных на стороне клиента, даже если на стороне клиента выполняется проверка. В целом, проверяйте все данные на стороне сервера. Если приложение использует JDBC, используйте PreparedStatement или CallableStatement с параметрами, передаваемыми с помощью '?' Если приложение использует ASP, используйте командные объекты ADO с строгой проверкой типов и параметризованными запросами. Если можно использовать хранимые процедуры базы данных, используйте их. *Не* объединяйте строки в запросах в хранимой процедуре и не используйте «exec», «exec immediate» или аналогичные функции! Не создавайте динамические SQL-запросы с помощью простого объединения строк. Экранируйте все данные, полученные от клиента. Применяйте «разрешённый список» допустимых символов или «запрещённый список» недопустимых символов во вводимых пользователем данных. Применяйте принцип наименьших привилегий, используя пользователя базы данных с наименьшими привилегиями. В частности, не используйте пользователей базы данных 'sa' или 'db-owner'. Это не устранит SQL-инъекции, но минимизирует их влияние. Предоставьте минимальный доступ к базе данных, необходимый для работы приложения.",
  },
  {
    zapPluginId: "40025",
    name: "Раскрытие доверенности",
    description: "-",
    cvssScore: 0,
    riskLevel: "Средний",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Отключите метод «TRACE» на прокси-серверах, а также на исходном сервере веб-приложений. Отключите метод «OPTIONS» на прокси-серверах, а также на исходном сервере веб-приложений, если он не требуется для других целей, таких как «CORS» (совместное использование ресурсов между источниками). Настройте веб-серверы и серверы приложений с помощью пользовательских страниц ошибок, чтобы предотвратить утечку страниц ошибок, связанных с конкретным продуктом, в случае ошибок HTTP, таких как запросы 'TRACK' для несуществующих страниц. Настройте все прокси-серверы, серверы приложений и веб-серверы, чтобы предотвратить раскрытие информации о технологии и версии в заголовках HTTP-ответов 'Server' и 'X-Powered-By'.",
  },
  {
    zapPluginId: "40026",
    name: "Межсайтовый скриптинг (на основе DOM)",
    description:
      "Межсайтовый скриптинг (XSS) — это метод атаки, который заключается в отображении кода, предоставленного злоумышленником, в экземпляре браузера пользователя. Экземпляром браузера может быть стандартный веб-браузер или объект браузера, встроенный в программный продукт, например браузер в WinAmp, программу для чтения RSS-лент или почтовый клиент. Сам код обычно написан на HTML/JavaScript, но может также включать VBScript, ActiveX, Java, Flash или любую другую технологию, поддерживаемую браузером. Когда злоумышленник получает доступ к браузеру пользователя для выполнения своего кода, этот код будет работать в контексте безопасности (или зоне) веб-сайта, на котором он размещён. При таком уровне доступа код может считывать, изменять и передавать любые конфиденциальные данные, доступные браузеру. Пользователь, подвергшийся межсайтовому скриптингу, может столкнуться с захватом своей учётной записи (кражей файлов cookie), перенаправлением браузера в другое место или, возможно, с мошенническим контентом, предоставляемым веб-сайтом, который он посещает. Атаки с использованием межсайтового скриптинга, по сути, нарушают доверительные отношения между пользователем и веб-сайтом. Приложения, использующие экземпляры объектов браузера, которые загружают контент из файловой системы, могут выполнять код в зоне локальной машины, что позволяет скомпрометировать систему.",
    cvssScore: 0,
    riskLevel: "Высокий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Этап: архитектура и дизайн. Используйте проверенную библиотеку или фреймворк, которые не допускают возникновения этой уязвимости или предоставляют конструкции, позволяющие избежать этой уязвимости. Примеры библиотек и фреймворков, которые упрощают создание правильно закодированного вывода, включают библиотеку Microsoft Anti-XSS, модуль OWASP ESAPI Encoding и Apache Wicket. Этапы: реализация; архитектура и проектирование. Подумайте о контексте, в котором будут использоваться ваши данные, и о том, какая кодировка ожидается. Это особенно важно при передаче данных между различными компонентами или при создании вывода, который может содержать несколько кодировок одновременно, например веб-страниц или многокомпонентных почтовых сообщений. Изучите все ожидаемые протоколы связи и представления данных, чтобы определить необходимые стратегии кодирования. Для любых данных, которые будут выводиться на другую веб-страницу, особенно для данных, полученных из внешних источников, используйте соответствующую кодировку для всех небуквенно-цифровых символов. Для получения более подробной информации о необходимых типах кодирования и экранировании обратитесь к шпаргалке по предотвращению XSS. Этап: архитектура и проектирование. Для любых проверок безопасности, выполняемых на стороне клиента, убедитесь, что эти проверки дублируются на стороне сервера, чтобы избежать CWE-602. Злоумышленники могут обойти проверки на стороне клиента, изменив значения после выполнения проверок или изменив клиента так, чтобы полностью исключить проверки на стороне клиента. Затем эти изменённые значения будут отправлены на сервер. Если возможно, используйте структурированные механизмы, которые автоматически обеспечивают разделение данных и кода. Эти механизмы могут автоматически обеспечивать соответствующую обработку кавычек, кодировку и проверку, вместо того чтобы полагаться на то, что разработчик обеспечит эту возможность в каждой точке, где генерируется вывод. Этап: реализация Для каждой создаваемой веб-страницы используйте и указывайте кодировку символов, например ISO-8859-1 или UTF-8. Если кодировка не указана, веб-браузер может выбрать другую кодировку, предполагая, какая кодировка используется на веб-странице. Это может привести к тому, что веб-браузер будет рассматривать определённые последовательности как специальные, открывая клиента для скрытых XSS-атак.",
  },
  {
    zapPluginId: "40027",
    name: "SQL - инъекция - MsSQL",
    description: "Возможна SQL-инъекция",
    cvssScore: 0,
    riskLevel: "Высокий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    recommendation:
      "Не доверяйте вводу данных на стороне клиента, даже если на стороне клиента выполняется проверка. В целом, проверяйте все данные на стороне сервера. Если приложение использует JDBC, используйте PreparedStatement или CallableStatement с параметрами, передаваемыми с помощью '?' Если приложение использует ASP, используйте командные объекты ADO с строгой проверкой типов и параметризованными запросами. Если можно использовать хранимые процедуры базы данных, используйте их. *Не* объединяйте строки в запросах в хранимой процедуре и не используйте «exec», «exec immediate» или аналогичные функции! Не создавайте динамические SQL-запросы с помощью простого объединения строк. Экранируйте все данные, полученные от клиента. Применяйте «разрешённый список» допустимых символов или «запрещённый список» недопустимых символов во вводимых пользователем данных. Применяйте принцип наименьших привилегий, используя пользователя базы данных с наименьшими привилегиями. В частности, не используйте пользователей базы данных 'sa' или 'db-owner'. Это не устранит SQL-инъекции, но минимизирует их влияние. Предоставьте минимальный доступ к базе данных, необходимый для работы приложения.",
  },
  {
    zapPluginId: "40028",
    name: "Утечка информации ELMAH",
    description:
      "Модуль HTTP-запросов для регистрации ошибок (ELMAH [elmah.axd]) оказался доступен. Этот модуль может передавать значительный объём ценной информации.",
    cvssScore: 0,
    riskLevel: "Средний",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Подумайте, действительно ли ELMAH необходим в рабочей среде. Если нет, то отключите его. Если да, то убедитесь, что доступ к нему требует аутентификации и авторизации. См. также: https://elmah.github.io/a/securing-error-log-pages/",
  },
  {
    zapPluginId: "40029",
    name: "Отслеживание утечки Trace.axd",
    description:
      "Было обнаружено, что средство просмотра трассировки ASP.NET (trace.axd) доступно. Этот компонент может выдавать значительный объём ценной информации.",
    cvssScore: 0,
    riskLevel: "Средний",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Подумайте, действительно ли Trace Viewer необходим в рабочей среде. Если нет, то отключите его. Если да, то убедитесь, что для доступа к нему требуется аутентификация и авторизация.",
  },
  {
    zapPluginId: "40031",
    name: "Внеполосный XSS",
    description:
      "Межсайтовый скриптинг (XSS) — это метод атаки, который заключается в отображении кода, предоставленного злоумышленником, в экземпляре браузера пользователя. Экземпляром браузера может быть стандартный веб-браузер или объект браузера, встроенный в программный продукт, например браузер в WinAmp, программу для чтения RSS-лент или почтовый клиент. Сам код обычно написан на HTML/JavaScript, но может также включать VBScript, ActiveX, Java, Flash или любую другую технологию, поддерживаемую браузером. Когда злоумышленник получает доступ к браузеру пользователя для выполнения своего кода, этот код будет работать в контексте безопасности (или зоне) веб-сайта, на котором он размещён. При таком уровне доступа код может считывать, изменять и передавать любые конфиденциальные данные, доступные браузеру. Пользователь, подвергшийся межсайтовому скриптингу, может столкнуться с захватом своей учётной записи (кражей файлов cookie), перенаправлением браузера в другое место или, возможно, с мошенническим контентом, предоставляемым веб-сайтом, который он посещает. Атаки с использованием межсайтового скриптинга, по сути, нарушают доверительные отношения между пользователем и веб-сайтом. Приложения, использующие экземпляры объектов браузера, которые загружают контент из файловой системы, могут выполнять код в зоне локальной машины, что позволяет скомпрометировать систему.",
    cvssScore: 0,
    riskLevel: "Высокий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Этап: архитектура и дизайн. Используйте проверенную библиотеку или фреймворк, которые не допускают возникновения этой уязвимости или предоставляют конструкции, позволяющие избежать этой уязвимости. Примеры библиотек и фреймворков, которые упрощают создание правильно закодированного вывода, включают библиотеку Microsoft Anti-XSS, модуль OWASP ESAPI Encoding и Apache Wicket. Этапы: реализация; архитектура и проектирование. Подумайте о контексте, в котором будут использоваться ваши данные, и о том, какая кодировка ожидается. Это особенно важно при передаче данных между различными компонентами или при создании вывода, который может содержать несколько кодировок одновременно, например веб-страниц или многокомпонентных почтовых сообщений. Изучите все ожидаемые протоколы связи и представления данных, чтобы определить необходимые стратегии кодирования. Для любых данных, которые будут выводиться на другую веб-страницу, особенно для данных, полученных из внешних источников, используйте соответствующую кодировку для всех небуквенно-цифровых символов. Для получения более подробной информации о необходимых типах кодирования и экранировании обратитесь к шпаргалке по предотвращению XSS. Этап: архитектура и проектирование. Для любых проверок безопасности, выполняемых на стороне клиента, убедитесь, что эти проверки дублируются на стороне сервера, чтобы избежать CWE-602. Злоумышленники могут обойти проверки на стороне клиента, изменив значения после выполнения проверок или изменив клиента так, чтобы полностью исключить проверки на стороне клиента. Затем эти изменённые значения будут отправлены на сервер. Если возможно, используйте структурированные механизмы, которые автоматически обеспечивают разделение данных и кода. Эти механизмы могут автоматически обеспечивать соответствующую обработку кавычек, кодировку и проверку, вместо того чтобы полагаться на то, что разработчик обеспечит эту возможность в каждой точке, где генерируется вывод. Этап: реализация Для каждой создаваемой веб-страницы используйте и указывайте кодировку символов, например ISO-8859-1 или UTF-8. Если кодировка не указана, веб-браузер может выбрать другую кодировку, предполагая, какая кодировка используется на веб-странице. Это может привести к тому, что веб-браузер будет рассматривать определённые последовательности как специальные, открывая клиента для скрытых XSS-атак.",
  },
  {
    zapPluginId: "40032",
    name: "Утечка информации о .htaccess",
    description:
      "Файлы htaccess можно использовать для изменения конфигурации программного обеспечения веб-сервера Apache, чтобы включить/отключить дополнительные функции и возможности, которые предлагает программное обеспечение веб-сервера Apache.",
    cvssScore: 0,
    riskLevel: "Средний",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation: "Убедитесь, что файл .htaccess недоступен.",
  },
  {
    zapPluginId: "40033",
    name: "Внедрение NoSQL - MongoDB",
    description: "Возможна инъекция запроса MongoDB.",
    cvssScore: 0,
    riskLevel: "Высокий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    recommendation:
      "Не доверяйте вводу данных на стороне клиента и экранируйте все данные на стороне сервера. Не используйте ввод данных запроса непосредственно в предложениях where и group и обновите все драйверы до последней доступной версии.",
  },
  {
    zapPluginId: "40034",
    name: "Утечка информации .env",
    description:
      "Похоже, что на сервере был обнаружен один или несколько файлов .env. В этих файлах часто содержатся учётные данные инфраструктуры или административных учётных записей, ключи API или приложений или другая конфиденциальная информация о конфигурации.",
    cvssScore: 0,
    riskLevel: "Средний",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation: "Убедитесь, что файл .env недоступен.",
  },
  {
    zapPluginId: "40035",
    name: "Найден скрытый файл",
    description:
      "Конфиденциальный файл был идентифицирован как доступный. Это может привести к утечке административной информации, сведений о конфигурации или учётных данных, которые могут быть использованы злоумышленниками для дальнейшей атаки на систему или проведения социальной инженерии.",
    cvssScore: 0,
    riskLevel: "Средний",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Подумайте, действительно ли этот компонент необходим в рабочей среде. Если нет, то отключите его. Если да, то обеспечьте доступ к нему с помощью соответствующей аутентификации и авторизации или ограничьте доступ внутренними системами или конкретными IP-адресами и т. д.",
  },
  {
    zapPluginId: "40036",
    name: "Правило сканирования JWT",
    description: "Сканер для поиска уязвимостей в реализациях JWT.",
    cvssScore: 0,
    riskLevel: "Средний",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:L/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Смотрите ссылку для получения дополнительной информации. Решение зависит от деталей реализации.",
  },
  {
    zapPluginId: "40038",
    name: "Обход 403",
    description:
      "Возможно, удастся обойти конечные точки 403. Правило сканирования отправило полезную нагрузку, которая сделала ответ доступным (код состояния 200).",
    cvssScore: 6.5,
    riskLevel: "Средний",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Для устранения уязвимости обхода 403 необходимо реализовать многоуровневую проверку прав доступа: 1) на уровне middleware для каждого запроса, 2) в бизнес-логике перед выполнением операций, 3) в ORM/DAO при работе с БД. Заблокируйте модификации заголовков (X-Original-URL, X-Rewrite-URL) и попытки path traversal (../, %2e%2e/). Ограничьте HTTP-методы (запретите PUT/DELETE для статики). Настройте логирование всех попыток доступа к 403-ресурсам с алертами при подозрительной активности. Используйте единый механизм авторизации (например, OPA) и регулярно тестируйте защиту с помощью ZAP/Burp Scanner.",
  },
  {
    zapPluginId: "40039",
    name: "Обман веб-кэша",
    description:
      "Возможен обман веб-кэша. Неавторизованный пользователь может просмотреть конфиденциальные данные на этой странице.",
    cvssScore: 0,
    riskLevel: "Средний",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Настоятельно рекомендуется воздержаться от классификации типов файлов, таких как изображения или таблицы стилей, исключительно по их URL-адресу и расширению. Вместо этого следует убедиться, что файлы кэшируются на основе их заголовка Content-Type.",
  },
  {
    zapPluginId: "40040-1",
    name: "Заголовок CORS",
    description:
      "Совместное использование ресурсов из разных источников (CORS) — это механизм на основе HTTP-заголовков, который позволяет серверу указывать любые другие источники (домены, схемы или порты), кроме своего собственного, из которых браузер должен разрешать загрузку ресурсов. Он ослабляет политику одного источника (SOP).",
    cvssScore: 0,
    riskLevel: "Информационный",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Если веб-ресурс содержит конфиденциальную информацию, в заголовке Access-Control-Allow-Origin должно быть правильно указано происхождение. В этом заголовке должны быть указаны только доверенные веб-сайты, которым требуется этот ресурс, с поддержкой наиболее безопасного протокола.",
  },
  {
    zapPluginId: "40040-2",
    name: "Неправильная Конфигурация CORS",
    description:
      "Эта неправильная настройка CORS может позволить злоумышленнику выполнять AJAX-запросы к уязвимому веб-сайту со вредоносной страницы, загруженной пользовательским агентом жертвы. Чтобы выполнять аутентифицированные AJAX-запросы, сервер должен указать заголовок «Access-Control-Allow-Credentials: true», а для заголовка «Access-Control-Allow-Origin» должно быть установлено значение null или домен вредоносной страницы. Даже если эта неправильная настройка не позволяет выполнять аутентифицированные AJAX-запросы, можно получить доступ к конфиденциальному контенту без аутентификации (например, к веб-сайтам внутренней сети). Вредоносная страница может принадлежать как вредоносному веб-сайту, так и надёжному веб-сайту с уязвимостями (например, XSS, поддержка HTTP без TLS, позволяющая внедрять код через MITM и т. д.).",
    cvssScore: 0,
    riskLevel: "Средний",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Если веб-ресурс содержит конфиденциальную информацию, в заголовке Access-Control-Allow-Origin должно быть правильно указано происхождение. В этом заголовке должны быть указаны только доверенные веб-сайты, которым требуется этот ресурс, с поддержкой наиболее безопасного протокола.",
  },
  {
    zapPluginId: "40040-3",
    name: "Неправильная Конфигурация CORS",
    description:
      "Эта неправильная настройка CORS может позволить злоумышленнику выполнять AJAX-запросы к уязвимому веб-сайту со вредоносной страницы, загруженной пользовательским агентом жертвы. Чтобы выполнять аутентифицированные AJAX-запросы, сервер должен указать заголовок «Access-Control-Allow-Credentials: true», а для заголовка «Access-Control-Allow-Origin» должно быть установлено значение null или домен вредоносной страницы. Даже если эта неправильная настройка не позволяет выполнять аутентифицированные AJAX-запросы, можно получить доступ к конфиденциальному контенту без аутентификации (например, к веб-сайтам внутренней сети). Вредоносная страница может принадлежать как вредоносному веб-сайту, так и надёжному веб-сайту с уязвимостями (например, XSS, поддержка HTTP без TLS, позволяющая внедрять код через MITM и т. д.).",
    cvssScore: 0,
    riskLevel: "Высокий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Если веб-ресурс содержит конфиденциальную информацию, в заголовке Access-Control-Allow-Origin должно быть правильно указано происхождение. В этом заголовке должны быть указаны только доверенные веб-сайты, которым требуется этот ресурс, с поддержкой наиболее безопасного протокола.",
  },
  {
    zapPluginId: "40041",
    name: "Отправить файл",
    description:
      "Правило сканирования загрузки файлов используется для поиска уязвимостей в функции загрузки файлов в веб-приложениях.",
    cvssScore: 0,
    riskLevel: "Средний",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Следуйте инструкциям, указанным по следующим ссылкам: 1. https://portswigger.net/kb/issues/00500980_file-upload-functionality 2. https://www.youtube.com/watch?v=CmF9sEyKZNo",
  },
  {
    zapPluginId: "40042",
    name: "Утечка информации о пружинном приводе",
    description:
      "Spring Actuator для мониторинга работоспособности включен и может раскрывать конфиденциальную информацию об этом приложении. Spring Actuator можно использовать для реального мониторинга, но следует соблюдать осторожность, чтобы не раскрывать слишком много информации о приложении или инфраструктуре, на которой оно работает.",
    cvssScore: 0,
    riskLevel: "Средний",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Отключите датчики состояния здоровья и другие датчики или ограничьте их использование администраторами.",
  },
  {
    zapPluginId: "40043-1",
    name: "Log4Shell (CVE-2021-44228)",
    description:
      "Функции Apache Log4j2 <= 2.14.1 JNDI, используемые в конфигурации, сообщениях журнала и параметрах, не защищают от атак злоумышленников, контролирующих LDAP и другие конечные точки, связанные с JNDI. Злоумышленник, который может управлять сообщениями журнала или параметрами сообщений журнала, может выполнять произвольный код, загружаемый с серверов LDAP, если включена подстановка сообщений. Начиная с версии log4j 2.15.0, это поведение по умолчанию отключено.",
    cvssScore: 0,
    riskLevel: "Высокий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    recommendation:
      "Обновите Log4j2 до версии 2.17.1 или более поздней. В предыдущих версиях (старше 2.10) такое поведение можно смягчить, установив для системного свойства «log4j2.formatMsgNoLookups» значение «true» или удалив класс JndiLookup из пути к классам (пример: zip -q -d log4j-core-*.jar org/apache/logging/log4j/core/lookup/JndiLookup.class). Java 8u121 (см. https://www.oracle.com/java/technologies/javase/8u121-relnotes.html) защищает от удалённого выполнения кода, устанавливая по умолчанию для «com.sun.jndi.rmi.object.trustURLCodebase» и «com.sun.jndi.cosnaming.object.trustURLCodebase» значение «false».",
  },
  {
    zapPluginId: "40043-2",
    name: "Log4Shell (CVE-2021-45046)",
    description:
      "Было обнаружено, что исправление для устранения уязвимости CVE-2021-44228 в Apache Log4j 2.15.0 было неполным в некоторых конфигурациях, отличных от стандартных. Это могло позволить злоумышленникам создавать вредоносные входные данные с помощью шаблона поиска JNDI, что приводило к утечке информации и удалённому выполнению кода в некоторых средах.",
    cvssScore: 0,
    riskLevel: "Высокий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    recommendation: "Обновите Log4j2 до версии 2.17.1 или более поздней.",
  },
  {
    zapPluginId: "40044",
    name: "Экспоненциальное расширение объекта (атака миллиардом смехов)",
    description:
      "Экспоненциальное расширение сущностей, или атака «миллиарда смехов», — это разновидность атаки типа «отказ в обслуживании» (DoS). Она нацелена на парсеры языков разметки, таких как XML или YAML, которые позволяют расширять макросы.",
    cvssScore: 0,
    riskLevel: "Средний",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N",
    recommendation:
      "Защита от такого рода атак включает ограничение памяти, выделяемой для отдельного парсера, если потеря документа допустима, или символическое представление сущностей и их ленивое расширение только тогда, когда (и в той мере, в какой) их содержимое будет использоваться.",
  },
  {
    zapPluginId: "40045",
    name: "Пружинная оболочка",
    description:
      "Похоже, что приложение уязвимо для CVE-2022-22965 (также известного как Spring4Shell) — удалённого выполнения кода (RCE) через привязку данных.",
    cvssScore: 0,
    riskLevel: "Высокий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    recommendation:
      "Обновите Spring Framework до версий 5.3.18, 5.2.20 или более поздних.",
  },
  {
    zapPluginId: "40046",
    name: "Подделка запроса на стороне сервера",
    description:
      "Веб-сервер получает удалённый адрес и извлекает содержимое этого URL-адреса, но не может гарантировать, что запрос отправляется в ожидаемое место назначения.",
    cvssScore: 0,
    riskLevel: "Высокий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Не принимайте удалённые адреса в качестве параметров запроса, а если вам это необходимо, убедитесь, что они соответствуют списку допустимых значений. В теле ответа был обнаружен токен-маячок из внешнего сервиса.",
  },
  {
    zapPluginId: "40047",
    name: "Text4shell (CVE-2022-42889)",
    description:
      "Apache Commons Text до версии 1.10.0 допускает выполнение удалённого кода при работе с ненадёжными входными данными из-за небезопасных настроек интерполяции по умолчанию.Apache Commons Text выполняет интерполяцию переменных, позволяя динамически вычислять и расширять свойства.Было показано, что приложение устанавливает первоначальный контакт с удалёнными серверами посредством интерполяции переменных и может быть уязвимо для выполнения удалённого кода (RCE).",
    cvssScore: 0,
    riskLevel: "Высокий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    recommendation:
      "Обновите Apache Commons Text до версии 1.10.0 или более поздней.",
  },
  {
    zapPluginId: "50007-1",
    name: "Конечная точка GraphQL поддерживает самоанализ",
    description:
      "В конечной точке GraphQL включена функция самоанализа. Самоанализ позволяет клиентам запрашивать схему и получать подробную информацию о полях, типах, входных данных и т. д., поддерживаемых конечной точкой GraphQL. Это может быть полезно злоумышленникам, так как позволяет создавать более целенаправленные запросы.",
    cvssScore: 0,
    riskLevel: "Информационный",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation: "Отключите самоанализ в конечной точке GraphQL.",
  },
  {
    zapPluginId: "50007-2",
    name: "Определена реализация сервера GraphQL",
    description:
      "Система использует GraphQL API (Примерная система GraphQL для Примерной технологии 1/2). GraphQL может представлять риски, если не настроен должным образом: раскрытие схемы, чрезмерные запросы, недостаточная авторизация.",
    cvssScore: 0,
    riskLevel: "Информационный",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "1. Отключите introspection в production. 2. Внедрите лимиты: глубину запросов (max-depth), сложность (complexity), частоту (rate-limiting). 3. Реализуйте авторизацию на уровне полей. 4. Запретите POST-запросы с application/graphql без CSRF-токенов. 5. Используйте persisted queries.",
  },
  {
    zapPluginId: "90001",
    name: "Небезопасное состояние просмотра JSF",
    description:
      "Ответ по следующему URL-адресу содержит значение ViewState, не имеющее криптографической защиты.",
    cvssScore: 0,
    riskLevel: "Средний",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Защитите VIEWSTATE с помощью MAC, специфичного для вашей среды.",
  },
  {
    zapPluginId: "90002",
    name: "Объект сериализации Java",
    description:
      "Похоже, что используется сериализация Java. Если проверка не выполнена должным образом, злоумышленник может отправить специально созданный объект. Это может привести к опасному «выполнению удалённого кода». Была обнаружена магическая последовательность, идентифицирующая JSO (Base64: rO0AB, необработанное значение: 0xac, 0xed, 0x00, 0x05).",
    cvssScore: 0,
    riskLevel: "Средний",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Десериализация ненадёжных данных по своей сути опасна, и её следует избегать.",
  },
  {
    zapPluginId: "90003",
    name: "Отсутствует Атрибут Целостности субресурса",
    description:
      "В теге скрипта или ссылки, обслуживаемой внешним сервером, отсутствует атрибут целостности. Тег целостности не позволяет злоумышленнику, получившему доступ к этому серверу, внедрять вредоносный контент.",
    cvssScore: 0,
    riskLevel: "Средний",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Десериализация ненадёжных данных по своей сути опасна, и её следует избегать.",
  },
  {
    zapPluginId: "90004-1",
    name: "Недостаточная изоляция сайта от уязвимости Spectre",
    description:
      "Заголовок Cross-Origin-Resource-Policy — это необязательный заголовок, предназначенный для защиты от атак по сторонним каналам, таких как Spectre. Ресурс должен быть специально настроен как доступный для совместного использования между разными источниками.",
    cvssScore: 0,
    riskLevel: "Низкий",
    cvssVector: "CVSS:4.0/AV:L/AC:H/AT:N/PR:N/UI:P/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N/E:U",
    recommendation:
      "Убедитесь, что сервер приложений/веб-сервер правильно устанавливает заголовок Cross-Origin-Resource-Policy и что для всех веб-страниц он устанавливает заголовок Cross-Origin-Resource-Policy на 'same-origin'. 'same-site' считается менее безопасным, и его следует избегать. Если ресурсы необходимо использовать совместно, установите заголовок на 'cross-origin'. По возможности убедитесь, что конечный пользователь использует современный веб-браузер, соответствующий стандартам и поддерживающий заголовок Cross-Origin-Resource-Policy (https://caniuse.com/mdn-http_headers_cross-origin-resource-policy).",
  },
  {
    zapPluginId: "90004-2",
    name: "Недостаточная изоляция сайта от уязвимости Spectre",
    description:
      "Заголовок Cross-Origin-Resource-Policy — это необязательный заголовок, предназначенный для защиты от атак по сторонним каналам, таких как Spectre. Ресурс должен быть специально настроен как доступный для совместного использования между разными источниками.",
    cvssScore: 0,
    riskLevel: "Низкий",
    cvssVector: "CVSS:4.0/AV:L/AC:H/AT:N/PR:N/UI:P/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N/E:U",
    recommendation:
      "Убедитесь, что сервер приложений/веб-сервер правильно устанавливает заголовок Cross-Origin-Resource-Policy и что для всех веб-страниц он устанавливает заголовок Cross-Origin-Resource-Policy на 'same-origin'. 'same-site' считается менее безопасным, и его следует избегать. Если ресурсы необходимо использовать совместно, установите заголовок на 'cross-origin'. По возможности убедитесь, что конечный пользователь использует современный веб-браузер, соответствующий стандартам и поддерживающий заголовок Cross-Origin-Resource-Policy (https://caniuse.com/mdn-http_headers_cross-origin-resource-policy).",
  },
  {
    zapPluginId: "90004-3",
    name: "Недостаточная изоляция сайта от уязвимости Spectre",
    description:
      "Заголовок Cross-Origin-Resource-Policy — это необязательный заголовок, предназначенный для защиты от атак по сторонним каналам, таких как Spectre. Ресурс должен быть специально настроен как доступный для совместного использования между разными источниками.",
    cvssScore: 0,
    riskLevel: "Низкий",
    cvssVector: "CVSS:4.0/AV:L/AC:H/AT:N/PR:N/UI:P/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N/E:U",
    recommendation:
      "Убедитесь, что сервер приложений/веб-сервер правильно устанавливает заголовок Cross-Origin-Resource-Policy и что для всех веб-страниц он устанавливает заголовок Cross-Origin-Resource-Policy на 'same-origin'. 'same-site' считается менее безопасным, и его следует избегать. Если ресурсы необходимо использовать совместно, установите заголовок на 'cross-origin'. По возможности убедитесь, что конечный пользователь использует современный веб-браузер, соответствующий стандартам и поддерживающий заголовок Cross-Origin-Resource-Policy (https://caniuse.com/mdn-http_headers_cross-origin-resource-policy).",
  },
  {
    zapPluginId: "90005-1",
    name: "Отсутствует заголовок Sec-Fetch-Site",
    description:
      "Указывает на связь между источником запроса и источником ответа.",
    cvssScore: 0,
    riskLevel: "Информационный",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Убедитесь, что заголовок Sec-Fetch-Site включен в заголовки запросов",
  },
  {
    zapPluginId: "90005-2",
    name: "Заголовок Sec-Fetch-Mode отсутствует",
    description:
      "Позволяет различать запросы на переход между HTML-страницами и запросы на загрузку ресурсов, таких как изображения, аудио и т.д.",
    cvssScore: 0,
    riskLevel: "Информационный",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Убедитесь, что заголовок Sec-Fetch-Mode включен в заголовки запросов.",
  },
  {
    zapPluginId: "90005-3",
    name: "Заголовок Sec-Fetch-Dest отсутствует",
    description:
      "Указывает, как и где будут использоваться данные. Например, если значение — аудио, то запрашиваемый ресурс должен быть аудиоданными, а не каким-либо другим типом ресурса.",
    cvssScore: 0,
    riskLevel: "Информационный",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Убедитесь, что заголовок Sec-Fetch-Dest включен в заголовки запросов.",
  },
  {
    zapPluginId: "90005-4",
    name: "Заголовок Sec-Fetch-User отсутствует",
    description:
      "Указывает, был ли навигационный запрос инициирован пользователем.",
    cvssScore: 0,
    riskLevel: "Информационный",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Убедитесь, что заголовок Sec-Fetch-User включен в запросы, инициированные пользователем.",
  },
  {
    zapPluginId: "90005-5",
    name: "Sec-Fetch-Site заголовок сайта имеет недопустимое значение",
    description:
      "Указывает на связь между источником запроса и источником ответа.",
    cvssScore: 0,
    riskLevel: "Информационный",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Заголовок Sec-Fetch-Site должен иметь одно из следующих значений: same-origin, same-site, cross-origin или none.",
  },
  {
    zapPluginId: "90005-6",
    name: "Заголовок Sec-Fetch-Mode имеет недопустимое значение",
    description:
      "Позволяет различать запросы на переход между HTML-страницами и запросы на загрузку ресурсов, таких как изображения, аудио и т.д.",
    cvssScore: 0,
    riskLevel: "Информационный",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Заголовок Sec-Fetch-Mode должен иметь одно из следующих значений: cors, no-cors, navigate, same-origin или websocket.",
  },
  {
    zapPluginId: "90005-7",
    name: "Заголовок Sec-Fetch-Dest имеет недопустимое значение",
    description:
      "Указывает, как и где будут использоваться данные. Например, если значение — аудио, то запрашиваемый ресурс должен быть аудиоданными, а не каким-либо другим типом ресурса.",
    cvssScore: 0,
    riskLevel: "Информационный",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Заголовок Sec-Fetch-Dest должен иметь одно из следующих значений: аудио, аудиоэлемент, документ, встраивание, пустое значение, шрифт, фрейм, iframe, изображение, манифест, объект, элемент рисования, отчёт, скрипт, служебный элемент, общий служебный элемент, стиль, трек, видео, элемент, xslt.",
  },
  {
    zapPluginId: "90005-8",
    name: "Заголовок Sec-Fetch-User имеет недопустимое значение",
    description:
      "Указывает, был ли навигационный запрос инициирован пользователем.",
    cvssScore: 0,
    riskLevel: "Информационный",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation: "Заголовок Sec-Fetch-User должен иметь значение ?1.",
  },
  {
    zapPluginId: "90011",
    name: "Charset Mismatch",
    description:
      "Эта проверка выявляет ответы, в которых заголовок HTTP Content-Type указывает кодировку, отличную от кодировки, указанной в теле HTML- или XML-документа. Если кодировка в заголовке HTTP не совпадает с кодировкой в теле документа, веб-браузеры могут перейти в нежелательный режим анализа содержимого, чтобы определить правильную кодировку содержимого. Злоумышленник может манипулировать содержимым страницы, чтобы оно интерпретировалось в выбранной им кодировке. Например, если злоумышленник может управлять содержимым в начале страницы, он может внедрить скрипт, использующий текст в кодировке UTF-7, и заставить некоторые браузеры интерпретировать этот текст.",
    cvssScore: 0,
    riskLevel: "Информационный",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Принудительно используйте UTF-8 для всего текстового содержимого в заголовке HTTP и метатегах в HTML или в объявлениях кодировки в XML.",
  },
  {
    zapPluginId: "90017",
    name: "Инъекция XSLT",
    description:
      "Возможна инъекция с использованием преобразований XSL, которая позволит злоумышленнику считывать системную информацию, читать и записывать файлы или выполнять произвольный код.",
    cvssScore: 0,
    riskLevel: "Средний",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Очищайте и анализируйте каждый пользовательский ввод, поступающий с любой клиентской стороны. В ответ на отправку токена XSLT были получены сообщения об ошибках, которые могут указывать на уязвимость к внедрению XSLT.",
  },
  {
    zapPluginId: "90018",
    name: "Расширенная SQL-инъекция",
    description:
      "SQL-инъекция может быть возможна с использованием прикрепленной полезной нагрузки.",
    cvssScore: 0,
    riskLevel: "Высокий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    recommendation:
      "Не доверяйте вводу данных на стороне клиента, даже если на стороне клиента выполняется проверка. В целом, проверяйте все данные на стороне сервера. Если приложение использует JDBC, используйте PreparedStatement или CallableStatement с параметрами, передаваемыми с помощью '?' Если приложение использует ASP, используйте командные объекты ADO с строгой проверкой типов и параметризованными запросами. Если можно использовать хранимые процедуры базы данных, используйте их. *Не* объединяйте строки в запросы в хранимой процедуре и не используйте «exec», «exec immediate» или аналогичные функции! Не создавайте динамические SQL-запросы с помощью простого объединения строк. Экранируйте все данные, полученные от клиента. Применяйте «разрешённый список» допустимых символов или «запрещённый список» недопустимых символов во вводе пользователя. Применяйте принцип наименьших привилегий, используя пользователя базы данных с наименьшими привилегиями. В частности, не используйте пользователей базы данных 'sa' или 'db-owner'. Это не устранит SQL-инъекции, но минимизирует их влияние. Предоставьте минимальный доступ к базе данных, необходимый для работы приложения.",
  },
  {
    zapPluginId: "90019-1",
    name: "Внедрение кода на стороне сервера - внедрение PHP-кода",
    description:
      "Возможна инъекция кода, в том числе пользовательского, который будет оцениваться механизмом сценариев.",
    cvssScore: 0,
    riskLevel: "Высокий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    recommendation:
      "Не доверяйте вводу данных на стороне клиента, даже если предусмотрена проверка на стороне клиента. В целом, проверяйте все данные на стороне сервера и экранируйте все данные, полученные от клиента. Избегайте использования функций eval() в сочетании с пользовательским вводом данных.",
  },
  {
    zapPluginId: "90019-2",
    name: "Внедрение кода на стороне сервера - ASP-внедрение кода",
    description:
      "Возможна инъекция кода, в том числе пользовательского, который будет оцениваться механизмом сценариев.",
    cvssScore: 0,
    riskLevel: "Высокий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    recommendation:
      "Не доверяйте вводу данных на стороне клиента, даже если предусмотрена проверка на стороне клиента. В целом, проверяйте все данные на стороне сервера и экранируйте все данные, полученные от клиента. Избегайте использования функций eval() в сочетании с пользовательским вводом данных.",
  },
  {
    zapPluginId: "90020",
    name: "Удаленное внедрение команды операционной системы",
    description:
      "Метод атаки, используемый для несанкционированного выполнения команд операционной системы. Эта атака возможна, когда приложение принимает ненадёжные входные данные для создания команд операционной системы небезопасным способом, включающим ненадлежащую очистку данных и/или ненадлежащий вызов внешних программ.",
    cvssScore: 0,
    riskLevel: "Высокий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    recommendation:
      "По возможности используйте вызовы библиотек, а не внешние процессы для воссоздания нужной функциональности. Запускайте свой код в «тюрьме» или аналогичной среде-песочнице, которая обеспечивает строгие границы между процессом и операционной системой. Это может эффективно ограничивать доступ к файлам в определённом каталоге или к командам, которые может выполнять ваше программное обеспечение. Примерами на уровне ОС являются «тюрьма» chroot в Unix, AppArmor и SELinux. В целом, управляемый код может обеспечивать некоторую защиту. Например, java.io.FilePermission в Java SecurityManager позволяет задавать ограничения на операции с файлами. Это может быть невыполнимым решением, и оно ограничивает воздействие только на операционную систему; остальная часть вашего приложения все еще может быть скомпрометирована. Что касается любых данных, которые будут использоваться для генерации команды, подлежащей выполнению, храните как можно больше этих данных вне внешнего контроля. Например, в веб-приложениях для этого может потребоваться сохранить команду локально в состоянии сеанса вместо отправки ее клиенту в скрытом поле формы. Используйте проверенную библиотеку или фреймворк, которые не допускают возникновения этой уязвимости или предоставляют конструкции, облегчающие ее устранение. Например, рассмотрите возможность использования элемента управления кодировкой ESAPI или аналогичного инструмента, библиотеки или фреймворка. Это поможет программисту кодировать выходные данные способом, менее подверженным ошибкам. Если вам необходимо использовать динамически генерируемые строки запроса или команды, несмотря на риск, правильно заключайте аргументы в кавычки и экранируйте любые специальные символы внутри этих аргументов. ",
  },
  {
    zapPluginId: "90021",
    name: "Внедрение XPath",
    description:
      "Инъекция XPath — это метод атаки, используемый для взлома приложений, которые создают запросы XPath (язык путей XML) на основе пользовательского ввода для запроса или навигации по XML-документам. Он может использоваться непосредственно приложением для запроса XML-документа в рамках более крупной операции, например, для применения преобразования XSLT к XML-документу или применения XQuery к XML-документу. Синтаксис XPath в некоторой степени напоминает синтаксис SQL-запросов, и действительно, с помощью XPath можно создавать SQL-подобные запросы к XML-документам. Если приложение использует построение запросов XPath во время выполнения и встраивает в запрос небезопасные пользовательские данные, злоумышленник может внедрить в запрос данные таким образом, что новый запрос будет проанализирован не так, как задумал программист.",
    cvssScore: 0,
    riskLevel: "Высокий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Используйте параметризованные запросы XPath (например, с помощью XQuery). Это поможет обеспечить разделение между плоскостью данных и плоскостью управления. Правильно проверяйте вводимые пользователем данные. Отклоняйте данные, где это уместно, фильтруйте, где это уместно, и экранируйте, где это уместно. Убедитесь, что входные данные, которые будут использоваться в запросах XPath, безопасны в этом контексте.",
  },
  {
    zapPluginId: "90022",
    name: "Раскрытие ошибок приложения",
    description:
      "Эта страница содержит сообщение об ошибке/предупреждении, которое может раскрывать конфиденциальную информацию, например, местоположение файла, вызвавшего необработанное исключение. Эта информация может быть использована для дальнейших атак на веб-приложение. Предупреждение может быть ложным, если сообщение об ошибке находится на странице документации.",
    cvssScore: 0,
    riskLevel: "Средний",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Просмотрите исходный код этой страницы. Внедрите пользовательские страницы ошибок. Рассмотрите возможность внедрения механизма, который будет предоставлять клиенту (браузеру) уникальную ссылку/идентификатор ошибки, сохраняя детали на стороне сервера и не предоставляя их пользователю.",
  },
  {
    zapPluginId: "90023",
    name: "Атака внешней сущности XML",
    description:
      "Этот метод использует одну из функций XML для динамического создания документов во время обработки. XML-сообщение может либо предоставлять данные явно, либо указывать на URI, где эти данные находятся. В рамках этого метода атаки внешние сущности могут заменять значение сущности вредоносными данными, альтернативными ссылками или могут нарушать безопасность данных, к которым имеет доступ сервер/приложение XML. Злоумышленники также могут использовать внешние сущности, чтобы сервер веб-сервисов загружал вредоносный код или контент на сервер для использования во вторичных или последующих атаках.",
    cvssScore: 0,
    riskLevel: "Высокий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Уязвимости внешних сущностей XML возникают из-за того, что библиотека синтаксического анализа XML в приложении поддерживает потенциально опасные функции XML. Чтобы предотвратить уязвимости внешних сущностей XML, отключите разрешение внешних сущностей и поддержку XInclude.",
  },
  {
    zapPluginId: "90024",
    name: "Универсальный Oracle заполнения",
    description:
      "Изменяя заполнение зашифрованной строки, злоумышленник может сгенерировать сообщение об ошибке, указывающее на вероятную уязвимость «оракла заполнения». Такая уязвимость может затронуть любое приложение или фреймворк, которые неправильно используют шифрование, например некоторые версии ASP.net, Java Server Faces и Mono. Злоумышленник может воспользоваться этой уязвимостью, чтобы расшифровать данные и восстановить ключи шифрования, потенциально просматривая и изменяя конфиденциальные данные. Это правило должно обнаруживать уязвимость MS10-070 «оракла заполнения» в ASP.net, если для этого включены пользовательские ошибки.",
    cvssScore: 0,
    riskLevel: "Высокий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Обновите программное обеспечение затронутого сервера или измените скрипты таким образом, чтобы они правильно проверяли зашифрованные данные перед попыткой расшифровки.",
  },
  {
    zapPluginId: "90025",
    name: "Внедрение языка выражения",
    description:
      "Программное обеспечение создаёт весь оператор языка выражений (EL) или его часть на странице Java Server (JSP) с использованием входных данных, полученных из вышестоящего компонента, но не нейтрализует или неправильно нейтрализует специальные элементы, которые могут изменить исходный оператор EL до его выполнения. В некоторых версиях Spring 3.0.5 и более ранних существовала уязвимость (CVE-2011-2730), из-за которой теги языка выражений оценивались дважды, что фактически делало любое приложение уязвимым для внедрения EL. Однако даже в более поздних версиях эта уязвимость всё ещё возможна в зависимости от конфигурации.",
    cvssScore: 0,
    riskLevel: "Высокий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    recommendation:
      "Выполняйте проверку данных на наличие ненадёжных входных данных и убедитесь, что при поступлении данных на уровень EL применяется кодировка вывода, чтобы интерпретатор не обнаружил метасимволы в пользовательском контенте до его оценки. Наиболее очевидные шаблоны для обнаружения включают ${ и #{, но эти данные можно закодировать или фрагментировать.",
  },
  {
    zapPluginId: "90026",
    name: "Подмена действия SOAP",
    description: "Сервер выполнил непреднамеренную операцию SOAP.",
    cvssScore: 0,
    riskLevel: "Высокий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Если это не требуется, атрибут SOAPAction следует отключить. При необходимости перед выполнением любой операции следует сравнить действие в SOAPAction и тело SOAP. Любое несоответствие следует рассматривать как атаку. Сервер выполнил непреднамеренную операцию SOAP.",
  },
  {
    zapPluginId: "90027",
    name: "Детектор провисания Cookie",
    description:
      "Повторяющиеся запросы GET: каждый раз добавляйте разные файлы cookie, а затем отправляйте обычный запрос со всеми файлами cookie, чтобы стабилизировать сеанс, и сравнивайте ответы с исходным базовым запросом GET. Это может выявить области, в которых аутентификация/атрибуты на основе файлов cookie фактически не применяются.",
    cvssScore: 0,
    riskLevel: "Информационный",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Файлы cookie, которые не имеют ожидаемого эффекта, могут выявить недостатки в логике приложения. В худшем случае это может показать, где аутентификация с помощью токенов cookie фактически не применяется. Эти файлы cookie повлияли на ответ: упс, эти файлы cookie НЕ повлияли на ответ: bar, foo",
  },
  {
    zapPluginId: "90028",
    name: "Небезопасный HTTP-метод",
    description:
      "Наиболее распространённая методика злоумышленников заключается в том, чтобы сначала изучить веб-присутствие цели и собрать как можно больше информации. Используя эту информацию, злоумышленник может разработать точный сценарий атаки, который позволит эффективно использовать уязвимость в типе/версии программного обеспечения, используемого целевым хостом. Многоуровневая идентификация по отпечатку похожа на своего предшественника, идентификацию по отпечатку TCP/IP (с помощью сканера, такого как Nmap), за исключением того, что она ориентирована на прикладной уровень модели OSI, а не на транспортный уровень. Теория, лежащая в основе этой идентификации по отпечатку, заключается в создании точного профиля целевой платформы, технологии веб-приложения, версии серверной базы данных, конфигураций и, возможно, даже сетевой архитектуры/топологии.",
    cvssScore: 0,
    riskLevel: "Средний",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Внедрите меры по сокрытию или маскировке информации о платформе системы, технологии веб-приложения, версии серверной базы данных, конфигурациях и архитектуре/топологии сети. Это может включать: 1. **Разнообразие платформ и программного обеспечения:** используйте сочетание технологий и платформ, чтобы злоумышленникам было сложнее составить точный профиль. 2. **Ложная информация:** вводите ложную или вводящую в заблуждение информацию в ответы системы, чтобы запутать инструменты для снятия цифровых отпечатков. 3. **Рандомизация ответов:** рандомизируйте определённые элементы ответов, чтобы злоумышленникам было сложнее постоянно идентифицировать систему. 4. **Правила брандмауэра:** внедрите правила брандмауэра, чтобы блокировать или ограничивать эффективность методов снятия отпечатков. 5. **Регулярные обновления:** обновляйте программное обеспечение, платформы и конфигурации, чтобы устранять известные уязвимости и предотвращать точную идентификацию на основе устаревшей информации. Универсального решения не существует, и наиболее эффективным может быть сочетание этих мер.",
  },
  {
    zapPluginId: "90029",
    name: "Внедрение SOAP XML",
    description: "Некоторый введенный XML-код был интерпретирован сервером.",
    cvssScore: 0,
    riskLevel: "Высокий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    recommendation:
      "Используйте подробное описание атрибутов SOAP в файле WSDL. Некоторый введенный XML-код был интерпретирован сервером.",
  },
  {
    zapPluginId: "90030",
    name: "Обнаружение файла WSDL",
    description: "Обнаружен файл WSDL.",
    cvssScore: 0,
    riskLevel: "Информационный",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Сделайте файлы WSDL видимыми только для решения технических проблем (например, в целях тестирования).",
  },
  {
    zapPluginId: "90033",
    name: "Cookie с широким охватом",
    description:
      "Область действия файлов cookie может быть ограничена доменом или путём. Эта проверка касается только области действия домена. Область действия домена, применяемая к файлу cookie, определяет, какие домены могут получить к нему доступ. Например, файл cookie может быть ограничен строго поддоменом, например www.nottrusted.com, или ограничен родительским доменом, например nottrusted.com. В последнем случае любой поддомен nottrusted.com может получить доступ к файлу cookie. Файлы cookie с широкой областью действия часто используются в мегаприложениях, таких как google.com и live.com. Файлы cookie, установленные на поддомене, например app.foo.bar, передаются браузером только на этот домен. Однако файлы cookie, установленные на родительском домене, могут передаваться на родительский домен или на любой поддомен родительского домена.",
    cvssScore: 0,
    riskLevel: "Информационный",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Всегда указывайте в файлах cookie полное доменное имя (FQDN). Исходный домен, использованный для сравнения: subdomain.example.com имя=значение",
  },
  {
    zapPluginId: "90034",
    name: "Потенциально уязвимые облачные метаданные",
    description:
      "Атака на метаданные облака — это попытка использовать неправильно настроенный сервер NGINX для доступа к метаданным инстансов, которые поддерживают поставщики облачных услуг, такие как AWS, GCP и Azure. Все эти поставщики предоставляют метаданные через внутренний немаршрутизируемый IP-адрес «169.254.169.254», который может быть раскрыт неправильно настроенными серверами NGINX и доступен через этот IP-адрес в поле заголовка Host.",
    cvssScore: 0,
    riskLevel: "Высокий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Не доверяйте никаким пользовательским данным в конфигурациях NGINX. В данном случае, вероятно, используется переменная $host, которая задаётся из заголовка «Host» и может контролироваться злоумышленником. На основании кода состояния успешного ответа в ответе могли быть возвращены метаданные облака. Проверьте данные ответа, были ли возвращены какие-либо метаданные облака. Возвращаемые метаданные могут содержать информацию, которая позволила бы злоумышленнику полностью скомпрометировать систему.",
  },
  {
    zapPluginId: "90035",
    name: "Внедрение шаблона на стороне сервера",
    description:
      "Когда пользовательский ввод вставляется в шаблон вместо того, чтобы использоваться в качестве аргумента при рендеринге, он оценивается механизмом шаблонов. В зависимости от механизма шаблонов это может привести к удалённому выполнению кода.",
    cvssScore: 0,
    riskLevel: "Высокий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    recommendation:
      "Вместо того чтобы вставлять пользовательский ввод в шаблон, используйте его в качестве аргумента рендеринга.",
  },
  {
    zapPluginId: "90036",
    name: "Внедрение шаблона на стороне сервера (слепое)",
    description:
      "Когда пользовательский ввод вставляется в шаблон вместо того, чтобы использоваться в качестве аргумента при рендеринге, он оценивается механизмом шаблонов. В зависимости от механизма шаблонов это может привести к удалённому выполнению кода.",
    cvssScore: 0,
    riskLevel: "Высокий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    recommendation:
      "Вместо того чтобы вставлять пользовательский ввод в шаблон, используйте его в качестве аргумента рендеринга.",
  },
  {
    zapPluginId: "90039",
    name: "Внедрение NoSQL - MongoDB (на основе времени)",
    description: "Возможна инъекция запроса MongoDB.",
    cvssScore: 0,
    riskLevel: "Высокий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    recommendation:
      "Не доверяйте вводу данных на стороне клиента и экранируйте все данные на стороне сервера. Не используйте ввод данных запроса непосредственно в предложениях where и group и обновите все драйверы до последней доступной версии. С помощью операторов where или group MongoDB функция Javascript sleep, вероятно, может быть выполнена.",
  },
  {
    zapPluginId: "100002",
    name: "Сервер работает на Clacks - GNU Terry Pratchett",
    description:
      "Веб-сервер/сервер приложений работает в сети Clacks, некоторые говорят, что это черепахи/IP, некоторые говорят, что это черепахи на всех уровнях стека.",
    cvssScore: 0,
    riskLevel: "Информационный",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Дайте системному администратору «пять» и радуйтесь жизни в мире дисков.",
  },
  {
    zapPluginId: "100003",
    name: "Набор файлов cookie без флага HttpOnly",
    description:
      "Файл cookie был создан без флага HttpOnly, что означает, что к файлу cookie может получить доступ JavaScript. Если на этой странице может быть запущен вредоносный скрипт, то файл cookie будет доступен и может быть передан на другой сайт. Если это файл cookie сеанса, то может произойти захват сеанса.",
    cvssScore: 0,
    riskLevel: "Низкий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N/E:U",
    recommendation:
      "Убедитесь, что флаг HttpOnly установлен для всех файлов cookie.",
  },
  {
    zapPluginId: "100004",
    name: "Включено сообщение о нарушениях Content Security Policy",
    description: "-",
    cvssScore: 0,
    riskLevel: "Информационный",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Владелец сайта будет получать уведомления о каждом нарушении правил, поэтому начните с анализа того, осуществляется ли реальный мониторинг уведомлений, прежде чем использовать фаззинг или действовать более агрессивно.",
  },
  {
    zapPluginId: "100005",
    name: "Используемая защита атрибута cookie SameSite",
    description: "-",
    cvssScore: 0,
    riskLevel: "Информационный",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Возможные уязвимости CSRF, присутствующие на сайте, будут устранены в зависимости от браузера, используемого пользователем (браузер определяет уровень поддержки этого атрибута файла cookie).",
  },
  {
    zapPluginId: "100006",
    name: "Раскрытие информации - IP-адрес, открытый через файл cookie F5 BIG-IP Persistence",
    description:
      "Файл cookie F5 BIG-IP Persistence, установленный для этого веб-сайта, можно расшифровать до конкретного IP-адреса и порта. Злоумышленник может использовать эту информацию для проведения атак с использованием социальной инженерии или других эксплойтов.",
    cvssScore: 0,
    riskLevel: "Информационный",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation: "Настройте шифрование файлов cookie с большим IP-адресом.",
  },
  {
    zapPluginId: "100007",
    name: "Раскрытие информации - строка в кодировке Base64",
    description:
      "В теле HTTP-ответа обнаружена строка в кодировке Base64. Данные в кодировке Base64 могут содержать конфиденциальную информацию, такую как имена пользователей, пароли или файлы cookie, которые необходимо дополнительно проверить.",
    cvssScore: 0,
    riskLevel: "Информационный",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Кодирование Base64 не следует использовать для хранения или отправки конфиденциальной информации.",
  },
  {
    zapPluginId: "100008",
    name: "Раскрытие информации - номер кредитной карты",
    description: "Номер кредитной карты был найден в теле HTTP-ответа.",
    cvssScore: 0,
    riskLevel: "Высокий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Шифруйте номера кредитных карт при передаче, используйте токенизацию и соблюдайте стандарты PCI DSS для безопасного обращения и хранения данных.",
  },
  {
    zapPluginId: "100009",
    name: "Раскрытие информации - адреса электронной почты",
    description:
      "В теле HTTP-ответа был обнаружен адрес электронной почты. Раскрытие адресов электронной почты в HTTP-сообщениях может привести к нарушению конфиденциальности и целенаправленным фишинговым атакам.",
    cvssScore: 0,
    riskLevel: "Низкий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N/E:U",
    recommendation:
      "Маскируйте адреса электронной почты при передаче и обеспечьте надлежащий контроль доступа для защиты конфиденциальности пользователей и предотвращения несанкционированного доступа.",
  },
  {
    zapPluginId: "100010",
    name: "Раскрытие информации - Хэш",
    description: "В теле HTTP-ответа был обнаружен хэш.",
    cvssScore: 0,
    riskLevel: "Низкий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N/E:U",
    recommendation:
      "Убедитесь, что хэши, которые используются для защиты учётных данных или других ресурсов, не передаются веб-сервером или базой данных. Как правило, нет необходимости предоставлять доступ к хэшам паролей веб-браузеру.",
  },
  {
    zapPluginId: "100011",
    name: "Раскрытие информации - комментарии в формате HTML",
    description:
      "Хотя добавление общих комментариев очень полезно, некоторые программисты склонны оставлять важные данные, такие как: имена файлов, связанных с веб-приложением, старые ссылки или ссылки, которые не предназначены для просмотра пользователями, старые фрагменты кода и т.д.",
    cvssScore: 0,
    riskLevel: "Информационный",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Удалите комментарии, содержащие конфиденциальную информацию о дизайне/разработке приложения. Некоторые комментарии могут быть доступны пользователю и влиять на безопасность приложения.",
  },
  {
    zapPluginId: "100012",
    name: "Раскрытие информации - номера IBAN",
    description: "В теле HTTP-ответа был обнаружен номер IBAN.",
    cvssScore: 0,
    riskLevel: "Низкий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N/E:U",
    recommendation:
      "Изучите номера IBAN, указанные в ответе, удалите или замаскируйте их по мере необходимости.",
  },
  {
    zapPluginId: "100013",
    name: "Раскрытие информации - частный IP-адрес",
    description:
      "В теле HTTP-ответа был обнаружен частный IP-адрес, например 10.x.x.x, 172.x.x.x, 192.168.x.x или IPV6 fe00::. Эта информация может быть полезна для дальнейших атак на внутренние системы.",
    cvssScore: 0,
    riskLevel: "Средний",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Удалите частный IP-адрес из тела HTTP-ответа. Для комментариев используйте комментарии JSP/ASP вместо комментариев HTML/JavaScript, которые могут быть видны в браузерах клиентов.",
  },
  {
    zapPluginId: "100014",
    name: "Отраженный параметр(ы) HTTP GET",
    description:
      "В HTTP-ответе было обнаружено отражённое значение параметра. Отражённые значения параметров могут привести к уязвимости XSS или внедрению HTTP-заголовков.",
    cvssScore: 0,
    riskLevel: "Информационный",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "1. Проверить контекст отражения: если данные выводятся внутри HTML-тегов/атрибутов или HTTP-заголовков — устранить риск XSS/инъекций. 2. Для профилактики: применить кодирование вывода (htmlspecialchars, escape-html) и валидацию входных параметров.",
  },
  {
    zapPluginId: "100015",
    name: "Методология HUNT",
    description:
      "Найдите возможные уязвимые точки входа, используя методологию ПОИСКА (https://github.com/bugcrowd/HUNT).",
    cvssScore: 0,
    riskLevel: "Информационный",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "1. Провести ручное тестирование обнаруженных точек входа по методике HUNT. 2. Особое внимание уделить: параметрам файлов (/download?file=), перенаправлениям (/redirect?url=), API-эндпоинтам. 3. Реализовать валидацию всех пользовательских входных данных. 4. Установить лимиты на обработку запросов. 5. Провести тестирование на: LFI/RFI, SSRF, открытые перенаправления, инъекции.",
  },
  {
    zapPluginId: "100016",
    name: "Отсутствующие заголовки безопасности",
    description:
      "В ответе HTTP отсутствуют некоторые из следующих заголовков безопасности: Strict-Transport-Security, Content-Security-Policy, X-XSS-Protection, X-Content-Type-Options, X-Frame-Options.",
    cvssScore: 0,
    riskLevel: "Низкий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N/E:U",
    recommendation:
      "Убедитесь, что ваш веб-сервер, сервер приложений, балансировщик нагрузки и т. д. настроены на установку отсутствующих заголовков безопасности.",
  },
  {
    zapPluginId: "100017",
    name: "Обнаружен нестатический Сайт",
    description:
      "В теле HTTP-ответа обнаружена строка запроса или форма. Это указывает на то, что это может быть не статичный сайт.",
    cvssScore: 0,
    riskLevel: "Информационный",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Если это не статический сайт, то игнорируйте или отключите это правило.",
  },
  {
    zapPluginId: "100018",
    name: "Перезапись относительного пути",
    description:
      "Обнаружена потенциальная уязвимость RPO (перезапись относительного пути). RPO позволяет злоумышленникам манипулировать URL-адресами, чтобы включать в них нежелательные пути, что потенциально может привести к выполнению вредоносных скриптов или раскрытию конфиденциальной информации.",
    cvssScore: 0,
    riskLevel: "Средний",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:L/VI:L/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Используйте абсолютные пути в URL-адресах и ресурсах, чтобы предотвратить манипуляции. Проверяйте и очищайте все вводимые пользователем данные, которые используются для создания URL-адресов.",
  },
  {
    zapPluginId: "100019",
    name: "Раскрытие информации - заголовок сервера",
    description:
      "Сервер веб-приложений передаёт информацию о версии через заголовок HTTP-ответа «Сервер». Доступ к такой информации может помочь злоумышленникам выявить другие уязвимости вашего сервера веб-приложений.",
    cvssScore: 0,
    riskLevel: "Низкий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N/E:U",
    recommendation:
      "Убедитесь, что ваш веб-сервер, сервер приложений, балансировщик нагрузки и т. д. настроены на скрытие заголовка «Сервер» или предоставление общих сведений.",
  },
  {
    zapPluginId: "100020",
    name: "Раскрытие информации - ошибка SQL",
    description: "В теле HTTP-ответа была обнаружена ошибка SQL.",
    cvssScore: 0,
    riskLevel: "Высокий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Убедитесь, что на стороне сервера выполнена надлежащая очистка.",
  },
  {
    zapPluginId: "100021",
    name: "Криптографическая уязвимость Telerik UI для ASP.NET AJAX (CVE-2017-9248)",
    description:
      "Был отправлен запрос, который, по-видимому, соответствует слабой криптографии, используемой Telerik UI для ASP.NET AJAX до версии 2017.2.621. Злоумышленник может манипулировать значением параметра dp, чтобы, возможно, узнать машинный ключ и загрузить произвольные файлы, что может привести к компрометации ASP.NET ViewStates и выполнению произвольного кода соответственно. CVE-2017-9248 имеет рейтинг CVSSv3 9,8.",
    cvssScore: 0,
    riskLevel: "Высокий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
    recommendation:
      "См. https://docs.telerik.com/devtools/aspnet-ajax/knowledge-base/common-cryptographic-weakness для получения рекомендаций по обновлению/защите.",
  },
  {
    zapPluginId: "100022",
    name: "Обнаружена форма для загрузки",
    description:
      "Наличие формы для загрузки файлов может привести к различным уязвимостям в системе безопасности, таким как загрузка вредоносных файлов или перезапись существующих файлов, если не реализованы надлежащие проверки и ограничения. Это может привести к несанкционированному выполнению кода, утечке данных или атакам типа «отказ в обслуживании».",
    cvssScore: 0,
    riskLevel: "Информационный",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Внедрите строгую проверку и ограничения для загружаемых файлов, включая тип, размер и содержимое. Используйте такие меры безопасности, как антивирусное сканирование и хранение файлов за пределами корневого каталога.",
  },
  {
    zapPluginId: "100023",
    name: "Раскрытие информации - заголовок X-Powered-By",
    description:
      "Сервер веб-приложений/серверов приложений передаёт информацию через один или несколько заголовков HTTP-ответа «X-Powered-By». Доступ к такой информации может помочь злоумышленникам определить другие фреймворки/компоненты, от которых зависит ваше веб-приложение, а также уязвимости, которым могут быть подвержены эти компоненты.",
    cvssScore: 0,
    riskLevel: "Низкий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N/E:U",
    recommendation:
      "Убедитесь, что ваш веб-сервер, сервер приложений, балансировщик нагрузки и т. д. настроены на подавление заголовков X-Powered-By.",
  },
  {
    zapPluginId: "100025",
    name: "Перехват межсайтового WebSocket",
    description:
      "Сервер принял подключение WebSocket через HTTP-запрос на обновление с измененным исходным заголовком.",
    cvssScore: 0,
    riskLevel: "Высокий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:P/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Проверяйте заголовок Origin при установлении соединения WebSocket, чтобы обеспечить возможность подключения только к указанным источникам. Кроме того, при установлении соединения WebSocket следует использовать случайные токены, аналогичные токенам защиты от CSRF.",
  },
  {
    zapPluginId: "100026",
    name: "JWT нет эксплойта",
    description:
      "Реализация JWT в приложении позволяет использовать алгоритм «без проверки», который позволяет обойти проверку хэша JWT.",
    cvssScore: 0,
    riskLevel: "Высокий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Используйте безопасную библиотеку JWT и (если ваша библиотека поддерживает это) ограничьте разрешённые алгоритмы хеширования.",
  },
  {
    zapPluginId: "100029",
    name: "Раскрытие содержимого файла (CVE-2019-5418)",
    description:
      "Похоже, что приложение уязвимо для CVE-2019-5418. С помощью специально составленного запроса можно было получить данные из файловой системы сервера.",
    cvssScore: 0,
    riskLevel: "Высокий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Обновите версию Ruby/Rails, в которой эта проблема устранена. (Дополнительные сведения см. в ссылках). (1)https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2019-5418 (2)https://github.com/mpgn/CVE-2019-5418",
  },
  {
    zapPluginId: "100030",
    name: "Обнаружен файл резервной копии",
    description:
      "Была обнаружена резервная или альтернативная версия страницы или компонента. Злоумышленник может использовать информацию из таких файлов для дальнейшей атаки или злоупотребления системой.",
    cvssScore: 0,
    riskLevel: "Низкий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N/E:U",
    recommendation:
      "Убедитесь, что резервные копии создаются в местах, недоступных через Интернет.",
  },
  {
    zapPluginId: "100034",
    name: "Раскрытие информации - ключ Google API",
    description: "Ключ Google API был найден в теле HTTP-ответа.",
    cvssScore: 0,
    riskLevel: "Информационный",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:L/SI:N/SA:N",
    recommendation:
      "Убедитесь, что ключ API не является чрезмерно разрешительным.",
  },
  {
    zapPluginId: "100035",
    name: "Раскрытие информации - трассировка стека Java",
    description: "В теле HTTP-ответа была обнаружена трассировка стека Java.",
    cvssScore: 0,
    riskLevel: "Средний",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Правильно обрабатывайте исключения, чтобы не показывать пользователям трассировку стека. Настройте веб-сервер или платформу приложений так, чтобы трассировка стека записывалась в журнал, а не отображалась.",
  },
  {
    zapPluginId: "100036",
    name: "Раскрытие информации - URL-адрес корзины Amazon S3",
    description: "URL-адрес корзины Amazon S3 был найден в теле HTTP-ответа.",
    cvssScore: 0,
    riskLevel: "Низкий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N/E:U",
    recommendation:
      "Удалите имена корзин S3 из ответа или убедитесь, что разрешения в корзине настроены правильно.",
  },
  {
    zapPluginId: "110001",
    name: "Раскрытие ошибок приложения через WebSockets",
    description:
      "Эта полезная нагрузка содержит сообщение об ошибке/предупреждении, которое может раскрыть конфиденциальную информацию, например, местоположение файла, вызвавшего необработанное исключение. Эта информация может быть использована для дальнейших атак на веб-приложение.",
    cvssScore: 0,
    riskLevel: "Средний",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Просмотрите сообщения об ошибках, которые передаются напрямую в WebSockets. Обработайте связанные с ними исключения. Рассмотрите возможность реализации механизма, который будет предоставлять клиенту (браузеру) уникальную ссылку/идентификатор ошибки, сохраняя подробности на стороне сервера и не раскрывая их пользователю.",
  },
  {
    zapPluginId: "110002",
    name: "Раскрытие Base64 в сообщении WebSocket",
    description:
      "В входящем сообщении веб-сокета была обнаружена строка в кодировке Base64. Данные в кодировке Base64 могут содержать конфиденциальную информацию, такую как имена пользователей, пароли или файлы cookie, которые следует проверить. Расшифрованное доказательство: пример.",
    cvssScore: 0,
    riskLevel: "Информационный",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Кодирование Base64 не следует использовать для хранения или отправки конфиденциальной информации.",
  },
  {
    zapPluginId: "110003",
    name: "Раскрытие информации - сообщения об ошибках отладки через WebSocket",
    description:
      "Судя по всему, ответ содержал распространённые сообщения об ошибках, возвращаемые такими платформами, как ASP.NET, и веб-серверами, такими как IIS и Apache. Вы можете настроить список распространённых сообщений об ошибках.",
    cvssScore: 0,
    riskLevel: "Низкий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N/E:U",
    recommendation:
      "Отключите отладочные сообщения перед запуском в производство.",
  },
  {
    zapPluginId: "110004",
    name: "Адрес электронной почты найден в сообщении WebSocket",
    description: "Адрес электронной почты был найден в сообщении WebSocket.",
    cvssScore: 0,
    riskLevel: "Информационный",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Удаляйте электронные письма, которые не являются общедоступными.",
  },
  {
    zapPluginId: "110005",
    name: "Личная информация позволяющая установить личность через WebSocket",
    description:
      "Ответ содержит информацию, позволяющую установить личность, например номер кредитной карты. Тип кредитной карты: не определено.",
    cvssScore: 0,
    riskLevel: "Высокий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "1. Немедленно прекратить передачу PII через WebSocket. 2. Реализовать end-to-end шифрование (AES-256). 3. Внедрить маскирование данных: 'card_number': '4242******4242'. 4. Добавить проверку прав доступа. 5. Логировать все попытки доступа с метаданными (IP, timestamp).",
  },
  {
    zapPluginId: "110006",
    name: "Раскрытие частной IP-информации через WebSocket",
    description:
      "Во входящем сообщении WebSocket был обнаружен частный IP-адрес (например, 10.x.x.x, 172.x.x.x, 192.168.x.x) или частное имя хоста Amazon EC2 (например, ip-10-0-56-78). Эта информация может быть полезна для дальнейших атак на внутренние системы.",
    cvssScore: 0,
    riskLevel: "Низкий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N/E:U",
    recommendation: "Удалите частный IP-адрес из сообщений WebSocket.",
  },
  {
    zapPluginId: "110007",
    name: "Хэш имени пользователя найден в сообщении WebSocket",
    description:
      "Пример хэша {Пример / контекст: Пример} был обнаружен во входящем сообщении WebSocket. Это может указывать на то, что приложение подвержено уязвимости небезопасной прямой ссылки на объект (IDOR). Потребуется ручное тестирование, чтобы выяснить, можно ли использовать это обнаружение.",
    cvssScore: 0,
    riskLevel: "Информационный",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Используйте косвенные ссылки на объекты для каждого пользователя или сеанса (создайте временное сопоставление во время использования). Или убедитесь, что каждое использование прямой ссылки на объект связано с проверкой авторизации, чтобы убедиться, что пользователь имеет доступ к запрашиваемому объекту.",
  },
  {
    zapPluginId: "110008",
    name: "Раскрытие информации - подозрительные комментарии в XML через WebSocket",
    description:
      "Похоже, что ответ содержит подозрительные комментарии, которые могут помочь злоумышленнику.",
    cvssScore: 0,
    riskLevel: "Информационный",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Удалите все комментарии, которые возвращают информацию, которая может помочь злоумышленнику, и устраните все проблемы, на которые они ссылаются.",
  },
  {
    zapPluginId: "110009",
    name: "Полное раскрытие Пути",
    description:
      "Полный путь к файлам, которые могут быть конфиденциальными, был раскрыт клиенту.",
    cvssScore: 0,
    riskLevel: "Низкий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N/E:U",
    recommendation:
      "Отключите просмотр каталогов на вашем веб-сервере. Обратитесь к документации по веб-серверу.",
  },
  {
    zapPluginId: "120000-1",
    name: "Раскрытие информации - информация в локальном хранилище браузера",
    description:
      "Информация была сохранена в локальном хранилище браузера. Это не является чем-то необычным или обязательно небезопасным — это информационное предупреждение было выдано, чтобы помочь вам лучше понять, что делает это приложение. Для получения более подробной информации см. вкладки «Клиент» — эта информация была задана непосредственно в браузере и поэтому не обязательно будет отображаться в таком виде в сообщениях HTTP(S).",
    cvssScore: 0,
    riskLevel: "Информационный",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Это информационное предупреждение, и никаких действий не требуется. Были заданы следующие данные (ключ=значение): ключ=значение. Обратите внимание, что это предупреждение будет отображаться только один раз для каждого URL + ключа.",
  },
  {
    zapPluginId: "120000-2",
    name: "Раскрытие информации - Информация в хранилище сеансов браузера",
    description:
      "Информация была сохранена в локальном хранилище браузера. Это не является чем-то необычным или обязательно небезопасным — это информационное предупреждение было выдано, чтобы помочь вам лучше понять, что делает это приложение. Для получения более подробной информации см. вкладки «Клиент» — эта информация была задана непосредственно в браузере и поэтому не обязательно будет отображаться в таком виде в сообщениях HTTP(S).",
    cvssScore: 0,
    riskLevel: "Информационный",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Это информационное предупреждение, и никаких действий не требуется. Были заданы следующие данные (ключ=значение): ключ=значение. Обратите внимание, что это предупреждение будет отображаться только один раз для каждого URL + ключа.",
  },
  {
    zapPluginId: "120001-1",
    name: "Раскрытие информации - конфиденциальная информация в локальном хранилище браузера",
    description:
      "Похоже, что конфиденциальная информация была сохранена в локальном хранилище браузера. Это может нарушать требования PCI и большинство организационных политик. Для получения более подробной информации см. вкладки «Клиент» — эта информация была задана непосредственно в браузере и поэтому не обязательно будет отображаться в таком виде в сообщениях HTTP(S).",
    cvssScore: 0,
    riskLevel: "Низкий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Не храните конфиденциальную информацию в хранилище браузера. ",
  },
  {
    zapPluginId: "120001-2",
    name: "Раскрытие информации - конфиденциальная информация в хранилище сеансов браузера",
    description:
      "Похоже, что конфиденциальная информация была сохранена в локальном хранилище браузера. Это может нарушать требования PCI и большинство организационных политик. Для получения более подробной информации см. вкладки «Клиент» — эта информация была задана непосредственно в браузере и поэтому не обязательно будет отображаться в таком виде в сообщениях HTTP(S).",
    cvssScore: 0,
    riskLevel: "Низкий",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:L/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Не храните конфиденциальную информацию в хранилище браузера. ",
  },
  {
    zapPluginId: "120002-1",
    name: "Раскрытие информации - JWT в локальном хранилище браузера",
    description:
      "JWT хранился в локальном хранилище браузера. Это опасно, потому что срок действия данных, хранящихся в локальном хранилище, не ограничен.",
    cvssScore: 0,
    riskLevel: "Средний",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Это информационное предупреждение, и никаких действий не требуется.",
  },
  {
    zapPluginId: "120002-2",
    name: "Раскрытие информации - JWT в хранилище сеансов браузера",
    description:
      "JWT-токен был сохранён в браузере в sessionStorage. Это не является чем-то необычным или обязательно небезопасным — это информационное предупреждение было выдано, чтобы помочь вам лучше понять, что делает это приложение. Для получения более подробной информации см. вкладки «Клиент» — эта информация была задана непосредственно в браузере и поэтому не обязательно будет отображаться в таком виде в сообщениях HTTP(S).",
    cvssScore: 0,
    riskLevel: "Информационный",
    cvssVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N",
    recommendation:
      "Храните JWT в sessionStorage, а не в localStorage, чтобы они удалялись при завершении сеанса.",
  },
];

async function seedDatabase() {
  try {
    await connectDB();

    // Очищаем коллекцию
    await Vulnerability.deleteMany();
    console.log("✅ Коллекция очищена");

    // Добавляем тестовые данные
    await Vulnerability.insertMany(vulnerabilitiesData);
    console.log("✅ Тестовые данные добавлены");

    // Проверяем количество записей
    const count = await Vulnerability.countDocuments();
    console.log(`📊 Всего уязвимостей в базе: ${count}`);

    process.exit(0);
  } catch (err) {
    console.error("❌ Ошибка при заполнении базы:", err);
    process.exit(1);
  }
}

seedDatabase();

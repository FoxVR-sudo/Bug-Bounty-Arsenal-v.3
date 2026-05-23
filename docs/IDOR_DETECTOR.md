# IDOR Detector Documentation

## 🎯 Общо

IDOR (Insecure Direct Object Reference) детекторът е активен security scanner, който открива уязвимости в authorization механизмите на приложението.

## 🔍 Какво прави

IDOR уязвимостите възникват когато приложението разкрива директни референции към вътрешни обекти (файлове, database records, API endpoints) без да прави правилна authorization проверка. Атакуващият може да манипулира ID-тата за да получи достъп до чужди ресурси.

### Детекторът:

1. **Идентифицира ID параметри** в URLs:
   - Числови IDs (напр. `/users/123`, `?id=456`)
   - UUIDs (`/docs/550e8400-e29b-41d4-a716-446655440000`)
   - MongoDB ObjectIds (`/items/507f1f77bcf86cd799439011`)
   - Common parameter names (`user_id`, `doc_id`, `order_id`, etc.)

2. **Генерира тестови IDs**:
   - За числови: nearby IDs (±1, ±10), edge cases (0, 1, 999999)
   - За UUIDs: randomly generated UUIDs
   - За ObjectIds: similar hex patterns

3. **Тества достъп**:
   - Прави заявки с променени IDs
   - Сравнява response codes, sizes и content
   - Открива unauthorized достъп до други обекти

4. **Анализира резултатите**:
   - Проверява дали различни IDs връщат валидни отговори
   - Изчислява confidence based на броя успешни tests
   - Определя severity базирано на parameter name и context

## 📊 Severity Levels

- **HIGH**: ID параметри с имена като `user_id`, `account_id` - най-чувствителни данни
- **MEDIUM**: Други ID параметри - потенциално чувствителна информация

## 🎓 Примери

### Example 1: User Profile IDOR
```
Original URL: https://api.example.com/profile?user_id=100
Test URLs:
  - https://api.example.com/profile?user_id=99  ✅ HTTP 200 (different user data!)
  - https://api.example.com/profile?user_id=101 ✅ HTTP 200 (different user data!)

Result: HIGH severity IDOR - unauthorized access to other users' profiles
```

### Example 2: Document IDOR
```
Original URL: https://app.example.com/documents/12345
Test URLs:
  - https://app.example.com/documents/12344 ✅ HTTP 200 (different document!)
  - https://app.example.com/documents/12346 ✅ HTTP 200 (different document!)

Result: MEDIUM severity IDOR - unauthorized document access
```

## 🛡️ Mitigation

За да предотвратите IDOR уязвимости:

1. **Authorization Checks**
   ```python
   # BAD - No authorization check
   def get_document(doc_id):
       return Document.get(doc_id)
   
   # GOOD - Check user permission
   def get_document(doc_id, current_user):
       doc = Document.get(doc_id)
       if doc.owner_id != current_user.id:
           raise PermissionDenied
       return doc
   ```

2. **Indirect Object References**
   ```python
   # Instead of: /documents/12345
   # Use mapping: /documents/abc123 -> internal_id=12345
   # And validate user owns abc123
   ```

3. **Role-Based Access Control (RBAC)**
   ```python
   @require_permission('document.read')
   def get_document(doc_id):
       return Document.get(doc_id)
   ```

4. **Use UUIDs instead of sequential IDs**
   ```python
   # BAD: Sequential IDs are predictable
   id = 1, 2, 3, 4, 5...
   
   # BETTER: UUIDs are random
   id = "550e8400-e29b-41d4-a716-446655440000"
   ```

5. **Audit Logging**
   ```python
   log.info(f"User {user_id} accessed document {doc_id}")
   # Monitor for suspicious patterns
   ```

## 🔧 Configuration

IDOR детекторът се активира автоматично при всяко сканиране. Може да се контролира чрез:

```bash
# Rate limiting за да не overwhelm-неш сървъра
python main.py -s targets.csv --consent -r 2  # 2 requests/second

# Concurrency
python main.py -s targets.csv --consent -c 5  # 5 concurrent connections
```

## 📈 Performance

- Всяко ID се тества с max 5 variant IDs
- Respect-ва `per_host_rate` за throttling
- Timeout: 15 seconds per request
- Limit: Max 3 IDOR findings per URL (за да не overwhelm репорта)

## 🎯 Real-World Impact

IDOR уязвимости са в **OWASP Top 10** (A01:2021 - Broken Access Control) и са изключително често срещани:

### Famous IDOR Bugs:
- **Instagram** - $10,000 bounty за IDOR в account deletion
- **Uber** - IDOR в rider/driver data endpoints
- **Facebook** - Multiple IDOR issues в various APIs
- **GitLab** - IDOR позволяваща достъп до private repos

### Typical Findings:
- User profile data leakage
- Private document access
- Order information disclosure
- Financial data exposure
- Admin panel access

## 📝 Example Report

```json
{
  "type": "IDOR (Insecure Direct Object Reference)",
  "severity": "high",
  "confidence": "medium",
  "url": "https://api.example.com/orders?order_id=12345",
  "vulnerable_parameter": "order_id",
  "parameter_location": "query",
  "original_id": "12345",
  "id_type": "numeric",
  "test_results": [
    {"test_id": "12344", "status": 200, "length": 1523},
    {"test_id": "12346", "status": 200, "length": 1489}
  ],
  "evidence": "Original ID '12345' can be replaced with other IDs...",
  "impact": "Unauthorized access to other users' orders",
  "recommendation": "Implement proper authorization checks"
}
```

## 🚀 Usage Tips

1. **Test с реални ID patterns**: Сканирай URLs с различни ID formats
2. **Check API endpoints**: RESTful APIs често имат IDOR issues
3. **Test path parameters**: `/users/123` е също толкова уязвим колкото `?id=123`
4. **Monitor rate limits**: Respect target's rate limiting
5. **Analyze responses**: Гледай не само status code, но и content

## ⚠️ Limitations

- Не открива IDOR в POST body parameters (само URL-based)
- Не тества complex authorization scenarios
- False positives възможни при publicly accessible resources
- Изисква predictable ID patterns

## 🔗 References

- [OWASP: Insecure Direct Object References](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/05-Authorization_Testing/04-Testing_for_Insecure_Direct_Object_References)
- [PortSwigger: Access Control Vulnerabilities](https://portswigger.net/web-security/access-control)
- [HackerOne: IDOR Examples](https://www.hackerone.com/vulnerability-and-compliance/what-insecure-direct-object-reference-idor)

---

**Добавено на**: 01 ноември 2025  
**Версия**: 1.0  
**Автор**: Safe Bug Bounty Scanner Team

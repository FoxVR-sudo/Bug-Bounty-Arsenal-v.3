# IDOR Testing Examples

## Quick Test Scenarios

### 1. Test Numeric ID in Query Parameter
```bash
# Create test file
cat > test_idor.csv << EOF
URL,Status
https://jsonplaceholder.typicode.com/users/1,in
https://jsonplaceholder.typicode.com/posts/1,in
https://jsonplaceholder.typicode.com/comments?postId=1,in
EOF

# Run scan
python main.py -s test_idor.csv --consent -r 2

# Check results
cat reports/report.json | grep -A 10 "IDOR"
```

### 2. Test Path-based IDs
```bash
cat > test_path_idor.csv << EOF
URL,Status
https://api.example.com/users/100,in
https://api.example.com/orders/12345,in
https://api.example.com/documents/abc123,in
EOF

python main.py -s test_path_idor.csv --consent
```

### 3. Expected Results

The IDOR detector will:

1. **Identify ID parameters**
   ```
   Found: user ID "1" in path
   Found: post ID "1" in path  
   Found: postId "1" in query
   ```

2. **Generate test cases**
   ```
   Testing IDs: 0, 2, -9, 11, 999999
   ```

3. **Compare responses**
   ```
   Original (ID=1): 200 OK, 437 bytes
   Test (ID=2):     200 OK, 439 bytes ✓ Different content!
   Test (ID=0):     200 OK, 433 bytes ✓ Different content!
   ```

4. **Report findings**
   ```json
   {
     "type": "IDOR (Insecure Direct Object Reference)",
     "severity": "high",
     "confidence": "medium",
     "evidence": "Successfully accessed 5 different objects",
     "test_results": [
       {"test_id": "0", "status": 200},
       {"test_id": "2", "status": 200}
     ]
   }
   ```

## Real API Testing

### Safe Public APIs for Testing

```bash
# JSONPlaceholder (safe test API)
https://jsonplaceholder.typicode.com/users/1
https://jsonplaceholder.typicode.com/posts/1
https://jsonplaceholder.typicode.com/albums/1

# These endpoints are INTENTIONALLY accessible - good for learning
```

### Bug Bounty Testing

```bash
# For actual bug bounty targets:
cat > my_targets.csv << EOF
URL,Status
https://target.com/api/v1/profile?user_id=YOUR_ID,in
https://target.com/api/orders/YOUR_ORDER_ID,in
https://target.com/documents/YOUR_DOC_ID,in
EOF

# Run with proper rate limiting
python main.py -s my_targets.csv --consent -r 1 -c 3

# Generate detailed report
python generate_detailed_report.py
```

## Verification Steps

After IDOR detection:

1. **Manual Verification**
   ```bash
   # Original request
   curl -H "Authorization: Bearer YOUR_TOKEN" \
        https://api.target.com/orders/12345
   
   # Test with different ID
   curl -H "Authorization: Bearer YOUR_TOKEN" \
        https://api.target.com/orders/12346
   
   # If you see DIFFERENT data → IDOR confirmed!
   ```

2. **Check for Authorization**
   ```python
   # The server should verify:
   if order.owner_id != current_user.id:
       raise PermissionDenied("Not authorized")
   ```

3. **Document the Bug**
   - Original ID and your user context
   - Test ID that revealed other user's data
   - Screenshots of different data
   - Impact assessment

## Common False Positives

### Public Resources
```
URL: /api/posts/1
Result: All posts are public → NOT a bug
```

### Different Response = Not Always IDOR
```
URL: /api/items/1
Test: /api/items/2
Both return 200 but items are meant to be public → Check context!
```

### Validation Required
```
Always verify:
1. Are these resources supposed to be private?
2. Do they belong to different users?
3. Is there a legitimate reason for access?
```

## Advanced Testing

### Test with Authentication
```bash
# Login and get token
TOKEN=$(curl -X POST https://api.target.com/login \
  -d '{"email":"your@email.com","password":"pass"}' | jq -r '.token')

# Test endpoints
curl -H "Authorization: Bearer $TOKEN" \
     https://api.target.com/profile?user_id=123
```

### Test Different ID Formats
```bash
# Numeric
?id=1, ?id=2, ?id=999999

# UUID
?id=550e8400-e29b-41d4-a716-446655440000

# Hash
?id=a1b2c3d4e5f6

# Base64
?id=MTIzNDU=
```

## Response Analysis

### Indicators of IDOR

✅ **Strong Indicators:**
- Same HTTP status code (200)
- Similar response size
- Different data in response
- Different user/object identifiers

❌ **Not IDOR:**
- 404 Not Found (object doesn't exist)
- 403 Forbidden (proper authorization)
- Same response for all IDs
- Error messages

### Example Comparison

```json
// Original ID=100
{
  "id": 100,
  "name": "Alice",
  "email": "alice@example.com",
  "balance": 1500
}

// Test ID=101 (IDOR!)
{
  "id": 101,
  "name": "Bob",
  "email": "bob@example.com",
  "balance": 2300
}
```

## Reporting to Bug Bounty

Include in your report:

1. **Title**
   ```
   IDOR in User Profile API - Unauthorized Access to Other Users' Data
   ```

2. **Severity**
   ```
   HIGH - Can access sensitive personal information of all users
   ```

3. **Steps to Reproduce**
   ```
   1. Login as user A (ID=100)
   2. Request: GET /api/profile?user_id=100
   3. Change to: GET /api/profile?user_id=101
   4. Observe: Can see user B's data without authorization
   ```

4. **Impact**
   ```
   - Access to PII of all users
   - Can view financial data
   - Privacy violation
   ```

5. **Proof**
   ```
   Screenshots + curl commands from report
   ```

---

**Remember:** Always test responsibly and only on targets where you have permission!

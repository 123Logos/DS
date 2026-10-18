# Avatar Content Review API

## Overview

Avatar uploads are asynchronous. The server stores a normalized JPEG in the
private `user_pic/avatar_pending` directory, submits a temporary HTTPS URL to
WeChat `wxa/media_check_async`, and only publishes the avatar after every file
in the batch receives `pass`.

The production prerequisites are:

- `WECHAT_APP_ID` and `WECHAT_APP_SECRET`
- `WECHAT_WXA_MSG_TOKEN`
- `HOST`, as an HTTPS public URL reachable by WeChat
- `WECHAT_CONTENT_SECURITY_ENABLED=true`
- migration `migrations/002_avatar_content_review.sql`, or a fresh database
  initialized by `database_setup.py`

The callback URL configured in the WeChat mini program backend is:
`https://<host>/wechat-wxa/msg`.

## POST /user/{user_id}/avatar

Uploads one to three avatar files and creates one review submission per file.

**Basic information**

- Method: `POST`
- Authentication: required, `Authorization: Bearer <access_token>`
- Permission: the authenticated user must be the `{user_id}` owner
- Request content type: `multipart/form-data`
- Success status: `200`
- Response content type: `application/json`

**Request parameters**

| Name | Location | Type | Required | Validation and meaning |
| --- | --- | --- | --- | --- |
| `user_id` | path | integer | yes | Positive internal user ID; must equal the authenticated user ID |
| `avatar_files` | body | file[] | no | Repeat the same field for 1-3 files; each file must have a `.jpg`, `.jpeg`, `.png`, or `.webp` suffix and be no larger than 2 MB |

An empty file list clears the current avatar and expires unfinished reviews.
The server decodes the image, verifies its actual content, applies EXIF
orientation, converts it to RGB JPEG, and limits the normalized image to
300x300 pixels. A renamed non-image file is rejected.

**Request example**

```http
POST /user/42/avatar HTTP/1.1
Host: api.example.com
Authorization: Bearer eyJ...
Content-Type: multipart/form-data; boundary=avatar-boundary

--avatar-boundary
Content-Disposition: form-data; name="avatar_files"; filename="avatar.png"
Content-Type: image/png

<binary image bytes>
--avatar-boundary--
```

**Success response**

```json
{
  "batch_id": "7f7e4b4f-4f31-4dc1-ae9a-9e9c5a68f9d2",
  "status": "pending",
  "items": [
    {"submission_id": 101, "status": "pending"}
  ],
  "message": "Avatar submitted for review",
  "avatar_urls": [],
  "uploaded_at": "2026-08-05T10:20:30Z"
}
```

| Response field | Type | Required | Meaning |
| --- | --- | --- | --- |
| `batch_id` | string or null | yes | UUID used to poll this upload batch; null when the request clears the avatar |
| `status` | string | yes | Batch status; normally `pending` immediately after upload |
| `items` | object[] | yes | One item per submitted file |
| `items[].submission_id` | integer | yes | Internal review submission ID |
| `items[].status` | string | yes | `pending`, `review`, `pass`, `risky`, `failed`, or `expired` |
| `message` | string or null | no | Human-readable result message |
| `avatar_urls` | string[] | yes | Kept for backward compatibility; empty while review is pending |
| `uploaded_at` | string | yes | UTC response creation timestamp |

**Clear response**

```json
{
  "batch_id": null,
  "status": "cleared",
  "items": [],
  "message": "Avatar cleared",
  "avatar_urls": [],
  "uploaded_at": "2026-08-05T10:20:30Z"
}
```

**Invalid request example**

```http
POST /user/42/avatar HTTP/1.1
Authorization: Bearer eyJ...
Content-Type: multipart/form-data

avatar_files=malware.exe
```

The response is `400` with `{"detail":"Only JPG, PNG, and WEBP images are supported"}`.

## GET /user/avatar/review/{batch_id}

Returns the current user's review status for an upload batch.

**Basic information**

- Method: `GET`
- Authentication: required, `Authorization: Bearer <access_token>`
- Permission: a batch is visible only to its owner
- Request content type: none
- Success status: `200`
- Response content type: `application/json`

**Request parameters**

| Name | Location | Type | Required | Validation and meaning |
| --- | --- | --- | --- | --- |
| `batch_id` | path | string | yes | The UUID returned by the upload endpoint |

There is no request body.

**Success response**

```json
{
  "batch_id": "7f7e4b4f-4f31-4dc1-ae9a-9e9c5a68f9d2",
  "status": "pass",
  "items": [
    {"submission_id": 101, "status": "pass"}
  ]
}
```

The batch status is calculated with this priority: `risky`, `failed`,
`expired`, all `pass`, `review`, then `pending`. The client should use the
published avatar URL from the next user-info response only after `pass`.

## DELETE /user/avatar

Clears the authenticated user's published avatar and expires all unfinished
avatar review submissions for that user.

**Basic information**

- Method: `DELETE`
- URL: `/user/avatar?user_id=42`
- Authentication: required
- Permission: `user_id` must equal the authenticated user ID
- Request content type: none
- Success status: `200`
- Response content type: `application/json`

**Request parameters**

| Name | Location | Type | Required | Meaning |
| --- | --- | --- | --- | --- |
| `user_id` | query | integer | yes | Positive internal user ID owned by the token |

There is no request body. The response is
`{"message":"Avatar cleared","success":true}`.

## WeChat callback and temporary media

`POST /wechat-wxa/msg` is a server-to-server endpoint. It validates the
`signature`, `timestamp`, and `nonce` query parameters with
`WECHAT_WXA_MSG_TOKEN`, accepts WeChat XML or JSON, handles the
`Event=wxa_media_check` callback, and returns the plain text body `success`.
The callback is idempotent: a terminal submission ignores duplicate callbacks.

The unlisted `GET /wechat-wxa/media/avatar/{media_token}` endpoint is only a
temporary media URL for WeChat. The token is stored only as SHA-256, the file
is served only while the submission is `pending` or `review` and before
`expires_at`, and the file is removed after pass, rejection, failure, clear,
or expiry. The endpoint must not be exposed through an authenticated browser
flow or cached by a reverse proxy.

## Status flow and client polling

```text
pending -> pass
pending -> review -> pass
pending -> risky
pending -> failed
pending/review -> expired
```

For a batch of multiple files, the server publishes none of them until every
item is `pass`. A `risky` or `failed` item invalidates the entire batch. Poll
the status endpoint every 2-5 seconds, stop at a terminal status, and refresh
user information after `pass`. Do not treat the initial `200` response as a
published-avatar success.

## Errors and compatibility

| HTTP status | Trigger | Example response |
| --- | --- | --- |
| `400` | Invalid extension, invalid image bytes, file over 2 MB, or more than 3 files | `{"detail":"Invalid image content"}` |
| `401` | Missing or invalid bearer token | `{"detail":"Not authenticated"}` |
| `403` | Token user does not own the target user ID | `{"detail":"无权修改其他用户头像"}` |
| `404` | Unknown batch ID for the authenticated user | `{"detail":"Avatar review record not found"}` |
| `409` | User has no bound mini program `openid` | `{"detail":"WeChat mini program identity is not bound"}` |
| `502` | WeChat content review submission failed | `{"detail":"Avatar review is temporarily unavailable"}` |
| `503` | Review is disabled or `HOST` is unavailable | `{"detail":"Avatar content review is disabled"}` |

The previous synchronous upload behavior is changed: an upload no longer
returns a usable avatar URL immediately. Existing clients may continue to
send `avatar_files` and ignore the new fields, but they must stop assuming
`avatar_urls` is populated and must poll `batch_id`. `update-profile` rejects
`avatar_path`; avatar changes must use this endpoint so that clients cannot
bypass review. The old direct-write helper in `services/user_service.py` has
been removed so internal callers cannot bypass review accidentally.

## Change record

| Before | After | Impact |
| --- | --- | --- |
| Upload wrote directly to the public avatar directory | Upload writes to a private pending directory and publishes only after `pass` | Clients must poll review status |
| `avatar_path` could be included in profile updates | `avatar_path` is rejected | Clients must use the avatar upload endpoint |
| No review callback table | `avatar_review_submissions` tracks each file and batch | Run the migration or initialize the new table |
| No temporary-file cleanup | Scheduler expires records every 10 minutes | Operations must keep the scheduler enabled |

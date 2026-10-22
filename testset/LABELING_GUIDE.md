# Labeling guide: Vietnamese chat-scam test set

| Field | Value |
|---|---|
| Guide version | 1.2 (generator changed to Codex by owner decision, 2026-10-22) |
| Date | 2026-10-22 |
| Author | Claude (claude-opus-5-5) wrote this guide and the seed catalog. The conversations are written by an OpenAI model through the Codex CLI (owner decision, 2026-10-22); the exact model is recorded in `provenance.generator.model` |
| Applies to | `testset/synthetic-v1/` (primary synthetic set), `testset/case-studies-real/` (optional, qualitative) and `devset/` (development set, Section 11) |
| Status | Not frozen. Section 9 freezes the *test set*. The guide version used is recorded by hash in the test-set manifest. |

Vietnamese text appears only inside example strings and inside source titles.

---

## 1. Purpose, scope and independence rules

### 1.1 Purpose

The test set measures one capability: **a system reads a Vietnamese chat conversation one message at a time and
decides, after each message, whether to alert the user that the conversation is a scam.**

Each conversation therefore carries two gold labels:

1. A **conversation-level label**: `scam` or `benign`.
2. A **turn-level label** (`alert_turn`): the index of the earliest message at which a careful, informed human
   reader has enough evidence to alert. It is `null` for benign conversations.

These labels support these measurements (the metric choice belongs to the evaluation stage, not to this guide):

- conversation-level precision, recall and F1;
- false alerts on benign conversations at any message;
- **premature alerts** on scam conversations (an alert at a message index lower than `alert_turn`), reported separately;
- **detection delay**, in messages, after `alert_turn`;
- an early-risk measure such as ERDE (Losada & Crestani, 2016, see [losada-crestani-erde-2016]).

### 1.2 Scope

| In scope | Out of scope (version 1) |
|---|---|
| One-to-one text chats on Zalo, Facebook Messenger, SMS and Telegram | Group chats with three or more participants |
| Vietnamese text, including no-diacritic text, teencode, regional vocabulary | Other languages, except loanwords and brand names |
| Non-text content as **text placeholders** (links, images, files, voice and video calls) | Real images, audio, video or OCR input |
| Scams that try to obtain money, credentials, device control or personal data by deception | Harassment, sextortion with real material, illegal-but-not-deceptive trade (for example a real usurious loan) |
| Synthetic conversations seeded from case-level facts of real reports | Copied real message text |

### 1.3 Independence rules (mandatory)

These rules protect the test set from the detection system. They apply to every agent and person that writes,
labels or checks test content.

1. The test-set author and every quality-control labeler **do not read the detection system**: no source code, no
   prompts, no rules, no evaluation scripts, no tests, no project design documents. In this repository, the author
   reads only `testset/`.
2. The author does not search the repository. The author uses only public web sources about scam patterns in
   Vietnam and about annotation methodology.
3. The test set is **frozen with a SHA-256 hash before any detection work** uses it (Section 9).
4. The test set is **evaluation-only**. It is never used to train, fine-tune, few-shot prompt or tune thresholds of
   the detection system.
5. The detection developers do not read individual test conversations or per-conversation results. They receive
   only aggregate metrics.
6. This guide is the public task contract. It defines what "scam" and "alert turn" mean, so the detection
   developers MAY read it. The held-out parts are the conversations, their per-conversation labels and the test
   seed catalog (`testset/seeds/`). Owner decision, 2026-10-22.
8. The development set (Section 11) is the only labeled data that the detection developers read. Its seed cases are
   disjoint from the test seed cases.
7. The generator (an OpenAI model through the Codex CLI) is a different model family from the detection model
   (Gemini) and from the second labeler (Claude, Section 8.2). The detection model is not used to generate, label or
   adjudicate test content.

---

## 2. Definitions

### 2.1 Roles and indexing

- **User**: the person whom the engine protects. The engine runs on the user's side of the chat.
- **Contact**: the other party in the one-to-one chat. A contact can be a real person, an organization, an SMS
  sender name (brandname), or a hijacked account.
- **Message**: one chat bubble. A message has one sender role.
- **Turn**: in this guide, "turn" means **one message**. It does not mean a pair of messages.
- **Message index**: the 0-based position of the message in the conversation. The first message has index 0.
  `alert_turn` and evidence indices use this index.
- **Prefix up to index t**: messages 0 to t, inclusive. The engine sees only this prefix when it decides after
  message t.

### 2.2 Conversation-level label

**`scam`**: at least one contact message, in the conversation, is part of an attempt to obtain money, credentials,
one-time codes, device control, biometric data or identity documents **by deception** about identity, purpose,
or the consequences of the requested action.

- The label does not depend on the outcome. A conversation in which the user refuses, verifies or detects the scam
  is still `scam`.
- The deceptive attempt must be visible in the text (Section 5). A scam that the text never reveals is not a valid
  `scam` conversation; the author does not write it.
- A conversation that starts as a real exchange and later becomes a scam (for example, a friend's account is hijacked
  in the middle of a chat history) is `scam`.

**`benign`**: no message in the conversation is part of such an attempt. Requests for money, codes, documents or
app installation MAY occur, but they come from a party whose identity and purpose the text makes consistent and
verifiable, and they follow the legitimate procedure of that party (Section 4).

### 2.3 Ambiguous cases: decision and justification

**Decision** (confirmed by the owner, 2026-10-22). The primary scored set contains only conversations that a careful reader can label `scam` or `benign`
from the text alone. A conversation that is genuinely ambiguous is **excluded from scoring**. It is kept in a
separate unscored file (`excluded.jsonl`) with the reason. The manifest reports the number of excluded
conversations per intended category.

A conversation is **genuinely ambiguous** when one of these conditions is true:

1. Two independent labelers, each following this guide, disagree on the conversation label, and the adjudicator
   cannot resolve the disagreement by a specific clause of this guide (Section 8.4).
2. The text is consistent with both a deceptive attempt and a legitimate request, and no message gives evidence
   for either side. Example: a saved contact asks to borrow money with no context, no recipient account details and
   no verification.
3. The conversation is in the out-of-scope gray zone (Section 1.2), for example an aggressive but real lender.

**Justification.**

- A binary scored label needs one correct answer. If ambiguous items stay in the scored set, metric differences
  between systems can come from label noise instead of detection quality.
- A third scored class ("ambiguous") would need its own correct system behavior. The owner has not defined that
  behavior, so this guide does not invent it.
- Silent removal would hide difficulty. Therefore the excluded file is kept and counted, and it can serve as a
  qualitative stress set.
- Risk: exclusion removes the hardest cases, so the scored set can overestimate performance on real traffic.
  Section 10 records this limitation.

The author does not write ambiguous conversations on purpose. The author writes each conversation so that its label
follows from the text. Exclusion is a quality-control result, not a generation target.

---

## 3. Scam-type taxonomy for Vietnam

### 3.1 How to read this section

- Each type has an identifier in `snake_case`. The identifier is the value of `scam_type` in the metadata.
- "Typical case-level facts" are the facts that a seed record may hold (Section 6.4): impersonated party, channel,
  lure, requested action, payment method.
- "Typical alert evidence" says which combination under Section 5 usually completes the alert condition.
- Source keys in brackets refer to the source list in Section 3.4. All sources were accessed on **2026-10-22**.
- Facts marked **(search summary)** come only from a search-result summary, not from a fetched page.
  Facts marked **(author description)** are the author's general description of the pattern; the cited source gives
  only the name of the pattern.

### 3.2 Scam types

#### `authority_impersonation` — police, procuracy or court impersonation

- **Definition.** The contact claims to be a police officer, prosecutor or court official. The contact says that the
  user is linked to a crime (money laundering, drug case, an unpaid fine). The contact demands money to "verify" or
  "protect" the user's assets, or demands account data.
- **Typical case-level facts.** Impersonated party: police, procuracy, court. Channel: phone call, then Zalo.
  Lure: fear of arrest, a fake case file or arrest warrant as an image. Requested action: transfer money to "prove"
  the source of funds, keep the call secret. Payment: bank transfer to a personal account.
- **Typical alert evidence.** Authority claim with a money transfer request, a secrecy demand or a threat of arrest.
- **Sources.** [cattt-24-forms-2023] item "Giả danh cơ quan công an, viện kiểm sát, tòa án gọi điện lừa đảo";
  [ca-hcm-16-methods-2023] item 1 (callers demand transfers to "prove" funds for an investigation).

#### `government_service_impersonation` — public services, VNeID, tax, social insurance

- **Definition.** The contact claims to be a commune or ward official, an area police officer, a tax officer or a
  social-insurance officer. The contact tells the user to update personal data, activate an electronic identity, or
  receive a refund through a link or an app that is not from the official app store.
- **Typical case-level facts.** Impersonated party: ward police, civil registry staff, tax office, social insurance.
  Channel: phone call, then a link on Zalo or Facebook. Lure: administrative reorganization, identity
  activation, tax settlement or refund. Requested action: install a fake VNeID, eTax or public-service app; open a
  link; provide OTP codes or a face scan. Payment: money is taken from the bank account after device takeover.
- **Typical alert evidence.** Official claim with a request to install an app from a link or to share an OTP or a
  face scan. Official advice says that police support identity activation only in person and that apps come only
  from the App Store or Google Play [bca-vneid-2025-07].
- **Sources.** [bca-vneid-2025-07]; [cuc-thue-hcm-fake-app-2023] (fake "HCMTAX" app, all money in the account
  taken); [cattt-24-forms-2023] item "Giả mạo trang thông tin điện tử, cơ quan, doanh nghiệp (BHXH, ngân hàng...)";
  [ca-hcm-16-methods-2023] item 8 (social-insurance impersonation, no further detail).

#### `utility_telecom_impersonation` — electricity company or mobile operator

- **Definition.** The contact claims to be staff of a power company or a mobile network operator. The contact
  threatens to cut electricity or lock the SIM card, or offers a refund. The contact asks the user to pay into a
  personal account, open a link, install an app or follow "SIM upgrade" steps.
- **Typical case-level facts.** Impersonated party: local power company (Điện lực), mobile operator. Channel: phone
  call, SMS, Zalo. Lure: unpaid bill, merger of power units, 10–15 % refund (search summary), SIM not standardized.
  Requested action: pay to a personal account, open a link, install an app, video call for "guidance". Payment: bank
  transfer; account takeover.
- **Typical alert evidence.** Utility claim with a payment request to a personal account, a link or an app install.
  EVN states that it does not ask customers to update personal data or open unknown links by phone or SMS
  [evn-merger-2025-06].
- **Sources.** [evn-merger-2025-06]; [cattt-24-forms-2023] item "Lừa đảo 'khóa SIM' vì chưa chuẩn hóa thuê bao";
  [ca-hcm-16-methods-2023] item 4 (SIM upgrade, SIM locked, linked bank account lost).

#### `bank_impersonation` — bank staff, bank SMS, card and reward-point phishing

- **Definition.** The contact claims to be a bank, its staff, or the State Bank. The contact uses a reason such as
  expiring reward points, a credit-limit increase, an annual-fee refund or an account lock. The contact sends a link to
  a lookalike site or asks for card data, a password or an OTP.
- **Typical case-level facts.** Impersonated party: a commercial bank, a finance company, the State Bank. Channel:
  SMS with a spoofed brandname, phone call, Zalo. Lure: reward points that expire, limit increase, fee refund.
  Requested action: open a link and enter card number, expiry date, CVV and OTP. Payment: card linked to a
  mobile wallet and drained.
- **Typical alert evidence.** Bank claim with a request for card data or OTP, or a link to a non-official domain.
  Vietcombank states that it does not request card data or OTP by phone, email, website or chat apps
  [vcb-reward-points-2026].
- **Sources.** [vcb-reward-points-2026]; [cattt-24-forms-2023] items "Thủ đoạn giả danh các công ty tài chính, ngân
  hàng" and "Lừa đảo SMS Brandname, phát tán tin nhắn giả mạo"; [ca-hcm-16-methods-2023] item 2.

#### `account_takeover_money_request` — hijacked or cloned account of a relative, friend or manager

- **Definition.** The contact uses a hijacked or cloned Zalo or Facebook account of someone the user knows. The
  contact asks to borrow money or to pay urgently. The contact may use a short, low-quality "video call" (deepfake)
  to win trust.
- **Typical case-level facts.** Impersonated party: relative, friend, company leader. Channel: Zalo, Messenger.
  Lure: urgent need, embarrassment, short deadline. Requested action: transfer to an account that does not belong to
  the claimed person; avoid a phone call. Payment: bank transfer.
- **Typical alert evidence.** Money request with an inconsistency: the recipient name differs from the claimed
  person, the contact refuses a voice call, the video call is short and choppy, or the contact's facts or style
  contradict the earlier history.
- **Sources.** [ca-hcm-16-methods-2023] items 11, 12, 13, 19 (hijacked accounts ask friends for loans; deepfake
  video calls; QR "voting" leads to Zalo takeover; fake leader accounts); [vpbank-deepfake-2023];
  [cattt-24-forms-2023] items "Đánh cắp tài khoản mạng xã hội, nhắn tin lừa đảo" and "Lừa đảo cuộc gọi video
  Deepfake, Deepvoice".

#### `relative_emergency` — teacher or medical staff reports a relative's emergency

- **Definition.** The contact claims to be a teacher, school staff or hospital staff. The contact says that the
  user's child or relative is in an emergency and that surgery needs money now.
- **Typical case-level facts.** Impersonated party: physical-education teacher, school medical staff, emergency
  doctor. Channel: phone call, SMS, Zalo. Lure: serious injury, correct names of child and parent. Requested action:
  urgent transfer; a second transfer to another account after a claimed failure. Payment: bank transfer.
- **Typical alert evidence.** Emergency claim with a transfer to a personal account and pressure that prevents
  verification with the school or hospital.
- **Sources.** [moet-teacher-2023] (Ministry of Education and Training warning; 14 cases, 825 million VND in
  Ho Chi Minh City); [cattt-24-forms-2023] item "Giả danh giáo viên/nhân viên y tế báo người thân đang cấp cứu".

#### `task_job_scam` — "easy work, high pay", online collaborator, pay-to-do-tasks

- **Definition.** The contact offers easy online work (liking videos, rating products, "processing orders"). Early
  tasks pay small sums. Later tasks require a deposit, and the contact invents errors or "frozen accounts" to get
  more deposits.
- **Typical case-level facts.** Impersonated party: brand staff, cinema staff, recruiter. Channel: Facebook,
  Telegram, Zalo. Lure: commission for simple tasks. Requested action: deposit money to receive larger tasks, pay to
  "unlock" the account. Payment: bank transfer; app wallet.
- **Typical alert evidence.** Job offer with a requirement to pay or deposit before earning, or a commission that
  depends on a prior deposit.
- **Sources.** [cattt-24-forms-2023] item "Lừa đảo tuyển CTV online"; [ca-hcm-16-methods-2023] items 7, 14, 15;
  pattern details (small first payouts, "task error", rising deposits) from a search summary of Vietnamese police
  warnings 2023–2024 **(search summary)**.

#### `investment_romance_scam` — online relationship that leads to a fake investment platform

- **Definition.** The contact builds a friendly or romantic relationship over days or weeks. The contact then
  introduces an investment in crypto, gold, foreign stocks or forex on an app or website. The user sees small
  profits, then is pushed to deposit more; withdrawal fails or needs a fee.
- **Typical case-level facts.** Impersonated party: a successful businessperson, engineer or doctor abroad, or an
  experienced investor. Channel: dating app, Facebook, Zalo, Telegram. Lure: affection, high and safe returns.
  Requested action: install or register on a platform, deposit, upgrade to "VIP", pay a withdrawal fee. Payment:
  bank transfer, crypto (USDT).
- **Typical alert evidence.** Promise of high or guaranteed returns with a request to deposit on an unlicensed
  platform, or a fee to withdraw. Relationship talk alone is not evidence. This type is the main **slow-build** type.
- **Sources.** [laichau-romance-2025]; [hanoi-koi-global-2025] (18 million VND "trial" credit, deposits up to
  350 million VND, a "VIP 1" upgrade of 30,000 USDT, loss over 600 million VND); [cattt-24-forms-2023] items "Lừa đảo
  đầu tư chứng khoán, tiền ảo, đa cấp" and "Lừa đảo tình cảm, dẫn dụ đầu tư tài chính...".

#### `parcel_customs_scam` — gift from a foreign friend held by "customs"

- **Definition.** An online friend says that they sent a valuable gift. Then a second contact, claiming to be
  customs or a delivery company, asks the user to pay a fee or tax to release the parcel.
- **Typical case-level facts.** Impersonated party: foreign friend, customs officer, international courier. Channel:
  Facebook, Zalo, SMS. Lure: gift with cash or jewelry. Requested action: pay customs tax or a "fine". Payment: bank
  transfer to a personal account.
- **Typical alert evidence.** Release fee for an unrequested parcel, paid to a personal account.
- **Sources.** [ca-hcm-16-methods-2023] item 6 (fake foreign admirer sends gifts; fake customs officer demands fees);
  [cattt-24-forms-2023] item "... gửi bưu kiện, trúng thưởng".

#### `prize_scam` — prize or lucky-draw win that requires a fee

- **Definition.** The contact says that the user won a prize. The contact asks for a tax, fee or shipping charge
  before delivery, or for card data to "receive" the prize.
- **Typical case-level facts.** Impersonated party: a brand, a TV show, an e-commerce platform. Channel: phone call,
  SMS, Zalo, Facebook. Lure: car, phone, cash. Requested action: pay fee or tax first. Payment: bank transfer.
- **Typical alert evidence.** Win notice with an advance payment request.
- **Sources.** [ca-hcm-16-methods-2023] item 5; [cattt-24-forms-2023] item "... trúng thưởng".

#### `loan_advance_fee` — fake fast loan with fees before disbursement

- **Definition.** The contact offers a fast loan with same-day disbursement. The contact collects identity documents
  and then demands fees (guarantee, insurance, "wrong account number" correction) before the loan is released.
  The loan never arrives.
- **Typical case-level facts.** Impersonated party: bank staff, finance company. Channel: Facebook advertisement,
  then Zalo. Lure: fast approval, no collateral. Requested action: send citizen-ID photos and household data; pay a
  guarantee or insurance fee. Payment: bank transfer.
- **Typical alert evidence.** A fee to be paid before the loan is disbursed, to a personal account.
- **Sources.** [hanoi-loan-2025-12]; [ca-hcm-16-methods-2023] items 3, 18; [cattt-24-forms-2023] item "Đánh cắp
  thông tin Căn cước công dân đi vay nợ tín dụng".

#### `delivery_shipper_scam` — fake shipper or delivery company

- **Definition.** The contact claims to be a shipper or a delivery company. The contact asks for payment for an
  order that the user did not place, claims a payment failed, or sends a link to "verify the order" or install a
  "tracking app".
- **Typical case-level facts.** Impersonated party: shipper, delivery company, online seller. Channel: phone call,
  Zalo, SMS. Lure: pending order, wrongly charged service of 2–10 million VND per month. Requested action: transfer
  money, open a verification link, install a tracking app, scan a QR code. Payment: bank transfer; device takeover.
- **Typical alert evidence.** Request to install an app or open a non-official link to verify an order, or repeated
  payment demands to "cancel" a service.
- **Sources.** [bca-shipper-2025-05].

#### `online_purchase_booking_scam` — fake seller, fake accommodation, fake tour or ticket

- **Definition.** The contact sells goods, rooms, tours or tickets that do not exist, or sells at an unrealistic
  price. The contact requires a deposit or full payment by transfer, then disappears.
- **Typical case-level facts.** Impersonated party: hotel or homestay, travel agent, airline agent, private seller.
  Channel: fake website, Facebook page (sometimes with a verified badge), Zalo. Lure: low price, "urgent tour
  resale", last room. Requested action: deposit or full payment before service. Payment: bank transfer to a personal
  account.
- **Typical alert evidence.** Deposit to a personal account that does not match the claimed business, with a price
  far below market or pressure to pay at once.
- **Sources.** [bca-tet-2026]; [ca-hcm-16-methods-2023] item 17 (fake airline ticket sites); [cattt-24-forms-2023]
  items "Lừa đảo 'combo du lịch giá rẻ'" and "Rao bán hàng giả hàng nhái trên sàn thương mại điện tử".

#### `fake_payment_wrong_transfer` — fake transfer receipt or "money sent by mistake"

- **Definition.** Variant one: a "buyer" sends a fake screenshot of a successful transfer and asks the seller to
  hand over goods or refund an "overpayment". Variant two: money arrives in the user's account, and a contact asks
  for it back to a different account, or later a "lender" claims it was a loan with interest.
- **Typical case-level facts.** Impersonated party: buyer, stranger who "sent by mistake", debt collector. Channel:
  Zalo, Messenger, SMS. Requested action: refund to an account different from the sender, ship goods before the money
  is confirmed in the bank app. Payment: bank transfer.
- **Typical alert evidence.** Refund request to a different account than the sender's, or pressure to deliver based
  on a screenshot only.
- **Sources.** [cattt-24-forms-2023] items "Giả mạo biên lai chuyển tiền thành công" and "Lừa đảo chuyển nhầm tiền
  vào tài khoản ngân hàng" (names only; mechanism details are **author description**).

#### `recovery_scam` — "we can recover your lost money or account"

- **Definition.** The contact offers to recover money that the user lost to an earlier scam, or to recover a hacked
  Facebook account. The contact claims to be a lawyer, a police unit, a hacker or a "recovery service". The contact
  asks for a fee first.
- **Typical case-level facts.** Impersonated party: lawyer, police, technical expert. Channel: Facebook comment or
  page, Zalo, Telegram. Lure: return of lost money. Requested action: pay a service fee or "tax" first; give
  account credentials. Payment: bank transfer.
- **Typical alert evidence.** Advance fee for recovery, or a request for account credentials or OTP.
- **Sources.** [cattt-24-forms-2023] items "Lừa đảo dịch vụ lấy lại tiền khi đã bị lừa" and "Lừa đảo dịch vụ lấy lại
  Facebook" (names only; mechanism details are **author description**).

#### `gambling_tip_scam` — paid lottery numbers, betting or gambling apps

- **Definition.** The contact sells "sure" lottery numbers (số đề) or betting tips, or invites the user to a
  gambling app that shows wins and then blocks withdrawal.
- **Typical case-level facts.** Channel: Facebook, Zalo, Telegram. Lure: guaranteed win. Requested action: pay for
  numbers, deposit in an app. Payment: bank transfer.
- **Typical alert evidence.** Payment for a "guaranteed" result, or deposit into an unlicensed app.
- **Sources.** [cattt-24-forms-2023] items "Lừa đảo cho số đánh đề" and "Cài cắm ứng dụng, link quảng cáo cờ bạc, cá
  độ, tín dụng đen"; [ca-hcm-16-methods-2023] item 10.

#### `child_targeted_scam` — child model casting, game items, scholarships

- **Definition.** The contact targets a child or a parent with a casting call for child models, free game items or a
  scholarship. The contact asks for fees, parent bank data or account credentials.
- **Typical case-level facts.** Impersonated party: casting agency, game publisher, school. Channel: Facebook,
  Zalo, game chat. Lure: casting selection, free items. Requested action: pay a registration or training fee;
  share a game or bank login. Payment: bank transfer, phone cards.
- **Typical alert evidence.** Fee for selection, or credentials request.
- **Sources.** [cattt-24-forms-2023] item "Chiêu trò lừa đảo tuyển người mẫu nhí" (name only; mechanism details are
  **author description**). The same warning states that 3 of the 24 forms target children [cattt-24-forms-2023-sggp].

### 3.3 Taxonomy summary with count targets

Counts are **scored** targets after quality control. The author generates about 15 % more (Section 7.1) to absorb
exclusions.

| `scam_type` | Full name | Scored target | Main sources |
|---|---|---:|---|
| `authority_impersonation` | Police, procuracy or court impersonation | 10 | [cattt-24-forms-2023], [ca-hcm-16-methods-2023] |
| `government_service_impersonation` | Public services, VNeID, tax, social insurance | 9 | [bca-vneid-2025-07], [cuc-thue-hcm-fake-app-2023] |
| `utility_telecom_impersonation` | Electricity company or mobile operator | 6 | [evn-merger-2025-06], [cattt-24-forms-2023] |
| `bank_impersonation` | Bank staff, bank SMS, card and reward-point phishing | 10 | [vcb-reward-points-2026], [cattt-24-forms-2023] |
| `account_takeover_money_request` | Hijacked or cloned account of a known person | 10 | [ca-hcm-16-methods-2023], [vpbank-deepfake-2023] |
| `relative_emergency` | Teacher or medical staff reports a relative's emergency | 5 | [moet-teacher-2023] |
| `task_job_scam` | Easy work, high pay; pay-to-do-tasks | 9 | [cattt-24-forms-2023], [ca-hcm-16-methods-2023] |
| `investment_romance_scam` | Relationship that leads to a fake investment platform | 9 | [laichau-romance-2025], [hanoi-koi-global-2025] |
| `parcel_customs_scam` | Gift held by "customs" | 5 | [ca-hcm-16-methods-2023] |
| `prize_scam` | Prize that requires a fee | 5 | [ca-hcm-16-methods-2023] |
| `loan_advance_fee` | Fake loan with fees before disbursement | 6 | [hanoi-loan-2025-12] |
| `delivery_shipper_scam` | Fake shipper or delivery company | 6 | [bca-shipper-2025-05] |
| `online_purchase_booking_scam` | Fake seller, accommodation, tour or ticket | 6 | [bca-tet-2026] |
| `fake_payment_wrong_transfer` | Fake receipt or "money sent by mistake" | 4 | [cattt-24-forms-2023] |
| `recovery_scam` | Recovery of lost money or account for a fee | 4 | [cattt-24-forms-2023] |
| `gambling_tip_scam` | Paid lottery numbers, betting apps | 3 | [cattt-24-forms-2023] |
| `child_targeted_scam` | Child model casting, game items, scholarships | 3 | [cattt-24-forms-2023] |
| **Total** | | **110** | |

**Basis of the counts.** No source in this guide gives a reliable national prevalence per type, so the counts are
not prevalence estimates. The author gives more weight to types that (a) official warnings repeat across years and
agencies, and (b) occur in chat channels rather than only in voice calls. Each type keeps at least 3 conversations so
that a per-type failure is visible. Per-type results with fewer than 10 conversations are descriptive only.

**Seed-case coverage.** Each scam conversation uses one seed case (Section 6.4). One seed case seeds at most
**3** conversations, and those conversations differ in at least two of: channel, lure, requested action, payment
method, persona. Therefore the 110 scored scam conversations need at least 37 distinct seed cases. The sources above
are the anchor sources; the author collects further case reports into `seeds/seed_catalog.jsonl` before generation.

### 3.4 Sources

All sources were accessed on 2026-10-22. "Fetched" means that the page was retrieved, and a fetch tool summarized
its content for the author; the author did not read the full original page. "Search summary" means that only a
search-engine result summary was available.

| Key | Publisher, title, date | URL | Access mode |
|---|---|---|---|
| `cattt-24-forms-2023` | Báo Hà Tĩnh, "24 chiêu lừa đảo trực tuyến tại Việt Nam", 2023-06-24; reports the list of 24 forms issued by Cục An toàn thông tin (then under Bộ Thông tin và Truyền thông) on 2023-06-23 | https://baohatinh.vn/24-chieu-lua-dao-truc-tuyen-tai-viet-nam-post250470.html | Fetched (full list of 24 names) |
| `cattt-24-forms-2023-vneconomy` | VnEconomy, "Bộ Thông tin và Truyền thông cảnh báo 24 hình thức lừa đảo đang diễn ra trên không gian mạng Việt Nam", 2023-06-23 | https://vneconomy.vn/bo-thong-tin-va-truyen-thong-canh-bao-24-hinh-thuc-lua-dao-dang-dien-ra-tren-khong-gian-mang-viet-nam.htm | Fetched (lists 22 of the 24 names) |
| `cattt-24-forms-2023-sggp` | Sài Gòn Giải Phóng, "Cảnh báo về 24 hình thức lừa đảo trên không gian mạng", 2023-06-24 | https://www.sggp.org.vn/canh-bao-ve-24-hinh-thuc-lua-dao-tren-khong-gian-mang-post694888.html | Fetched (three groups; counts by target group: older adults 15, children 3, students 13, workers 19) |
| `ca-hcm-16-methods-2023` | VietnamFinance, "Công an TP. HCM chỉ rõ 16 thủ đoạn lừa đảo trên mạng", 2023-09-08; Ho Chi Minh City Police | https://vietnamfinance.vn/cong-an-tp-hcm-chi-ro-16-thu-doan-lua-dao-tren-mang-d100408.html | Fetched (the text describes about 19 schemes; item numbers in this guide follow the fetch summary order) |
| `bca-vneid-2025-07` | Báo Thế giới và Việt Nam, "Bộ Công an hướng dẫn cách tránh thủ đoạn lừa đảo cài ứng dụng VNeID giả mạo", 2025-07-06; Bộ Công an warning of 2025-07-05 | https://baoquocte.vn/bo-cong-an-huong-dan-cach-tranh-thu-doan-lua-dao-cai-ung-dung-vneid-gia-mao-320048.html | Fetched |
| `cuc-thue-hcm-fake-app-2023` | Nhân Dân, "Cục Thuế Thành phố Hồ Chí Minh cảnh báo về hiện tượng giả mạo công chức cơ quan thuế", 2023-04-08 | https://nhandan.vn/cuc-thue-thanh-pho-ho-chi-minh-canh-bao-ve-hien-tuong-gia-mao-cong-chuc-co-quan-thue-post746901.html | Fetched |
| `evn-merger-2025-06` | VnEconomy, "Cảnh báo tình trạng lợi dụng sáp nhập, giả mạo nhân viên điện lực để lừa đảo", 2025-06-30; EVN warning | https://vneconomy.vn/canh-bao-tinh-trang-loi-dung-sap-nhap-gia-mao-nhan-vien-dien-luc-de-lua-dao.htm | Fetched. The 10–15 % refund variant and "EVNSPC does not collect bills via Zalo or SMS" are **search summary** only |
| `vcb-reward-points-2026` | Báo Đại biểu Nhân dân, "Vietcombank cảnh báo lừa đảo giả mạo tin nhắn SMS thông báo điểm thưởng hết hạn", 2026-06-29 | https://daibieunhandan.vn/vietcombank-canh-bao-lua-dao-gia-mao-tin-nhan-sms-thong-bao-diem-thuong-het-han-10421928.html | Fetched |
| `vpbank-deepfake-2023` | VPBank, "Cảnh giác với thủ đoạn lợi dụng công nghệ Deepfake để lừa đảo", 2023-04-21 | https://www.vpbank.com.vn/bi-kip-va-chia-se/retail-story-and-tips/goc-canh-giac/canh-giac-voi-thu-doan-loi-dung-cong-nghe-deepfake-de-lua-dao | Fetched |
| `moet-teacher-2023` | Luật sư Việt Nam, "Bộ Giáo dục và Đào tạo cảnh báo thủ đoạn mạo danh giáo viên gọi điện lừa đảo phụ huynh học sinh", 2023-03-20 | https://lsvn.vn/bo-giao-duc-va-dao-tao-canh-bao-thu-doan-mao-danh-giao-vien-goi-dien-lua-dao-phu-huynh-hoc-sinh-1679280711-a128783.html | Fetched |
| `laichau-romance-2025` | Luật sư Việt Nam, "Cảnh giác với thủ đoạn lừa đảo tình cảm qua mạng", 2025-04-17; Lai Châu Provincial Police | https://lsvn.vn/canh-giac-voi-thu-doan-lua-dao-tinh-cam-qua-mang-a156466.html | Fetched |
| `hanoi-koi-global-2025` | Luật sư Việt Nam, "Công an Hà Nội cảnh báo lừa đảo khi tham gia đầu tư tiền ảo trên ứng dụng Koi Global", 2025-08-13 | https://lsvn.vn/cong-an-ha-noi-canh-bao-lua-dao-khi-tham-gia-dau-tu-tien-ao-tren-ung-dung-koi-global-a161667.html | Fetched |
| `hanoi-loan-2025-12` | Luật sư Việt Nam, "Cảnh báo lừa đảo khi vay tiền online dịp cuối năm", 2025-12-01; Hanoi Police | https://lsvn.vn/canh-bao-lua-dao-khi-vay-tien-online-dip-cuoi-nam-a166524.html | Fetched |
| `bca-shipper-2025-05` | Luật sư Việt Nam, "Bộ Công an khuyến cáo các biện pháp phòng tránh khi bị các đối tượng xấu giả danh shipper để lừa đảo", 2025-05-21 | https://lsvn.vn/bo-cong-an-khuyen-cao-cac-bien-phap-phong-tranh-khi-bi-cac-doi-tuong-xau-gia-danh-shipper-de-lua-dao-a156308.html | Fetched |
| `bca-tet-2026` | Báo Lào Cai, "Bộ Công an cảnh báo chiêu lừa đảo trực tuyến dịp Tết và mùa lễ hội", 2026-01-29 | https://baolaocai.vn/bo-cong-an-canh-bao-chieu-lua-dao-truc-tuyen-dip-tet-va-mua-le-hoi-post892557.html | Fetched |
| `sbv-2345-biometric` | LuatVietnam, "Từ 01/7/2024, chuyển khoản trên 10 triệu đồng phải xác thực sinh trắc học" (State Bank Decision 2345/QĐ-NHNN of 2023-12-18, effective 2024-07-01) | https://luatvietnam.vn/tin-van-ban-moi/tu-2024-chuyen-khoan-tren-10-trieu-dong-phai-xac-thuc-sinh-trac-hoc-186-96491-article.html | Fetched (secondary report, not the decision text) |
| `prescam-2026` | Sun et al., "PreScam: A Benchmark for Predicting Scam Progression from Early Conversations", arXiv:2605.12243, 2026-05-12 | https://arxiv.org/abs/2605.12243 | Fetched (abstract and HTML). 11,573 instances from 177,989 user reports; 20 categories (names not retrieved); three-stage kill chain (Initial Contact, Engagement, Termination); nine psychological-technique labels; alert time at 10 % false-positive rate |
| `cova-x-2026` | Lochstampfor & Roy, "An Expanded Synthetic Conversation Dataset for Multi-Turn Smishing Detection" (COVA-X), arXiv:2606.06879 | https://arxiv.org/abs/2606.06879 | Fetched (abstract and HTML). English only; 10,985 synthetic conversations, 8 categories; generation artifacts (contamination across types, label mismatch 49.8 % before cleanup, stage-direction bleed, salience bias) |
| `anatomy-conv-scams-2026` | Yuan et al., "The Anatomy of Conversational Scams: A Topic-Based Red Teaming Analysis of Multi-Turn Interactions in LLMs", arXiv:2601.03134 | https://arxiv.org/abs/2601.03134 | Fetched (abstract only). LLM-to-LLM simulation, English and Chinese; recurring escalation patterns; defenders use verification, delay, channel control. No explicit stage model in the abstract |
| `losada-crestani-erde-2016` | Losada & Crestani, "A Test Collection for Research on Depression and Language Use", CLEF 2016, LNCS 9822, pp. 28–39, doi:10.1007/978-3-319-44564-9_3 | https://doi.org/10.1007/978-3-319-44564-9_3 | **Search summary** (bibliographic data and the existence of the ERDE measure) |
| `artstein-poesio-2008` | Artstein & Poesio, "Inter-Coder Agreement for Computational Linguistics", Computational Linguistics 34(4):555–596, doi:10.1162/coli.07-034-R2 | https://aclanthology.org/J08-4004/ | **Search summary** |
| `vncert-5656` | Reporting channels: Trang cảnh báo an toàn thông tin Việt Nam (canhbao.khonggianmang.vn) and SMS short code 156/5656 | https://daibieunhandan.vn/tuan-dau-nam-2025-co-6-685-phan-anh-lua-dao-truc-tuyen-10357122.html | **Search summary** (current status of these channels not verified) |

---

## 4. Hard-negative (benign) categories

### 4.1 Rules for every benign conversation

1. No message is part of a deceptive attempt (Section 2.2).
2. At no prefix does the alert condition of Section 5 hold.
3. The benign reading follows from the text. When a benign conversation contains a sensitive request, the text
   also contains the consistency evidence that makes it legitimate (Section 5.4).
4. A **hard negative** contains at least one surface feature that a scam of a named type also has: a money request,
   a link, an OTP, an authority or bank name, urgency, a prize, a job offer, an investment topic. Its metadata names
   the scam type that it resembles (`resembles_scam_type`).
5. Legitimate procedures follow the published behavior of the real organization. Examples: the bank sends an OTP
   *to* the user and the message says not to share it; the State Bank rule requires biometric verification inside
   the bank app for transfers above 10 million VND [sbv-2345-biometric]; ward police ask the user to come in person
   for identity matters [bca-vneid-2025-07]; a real shipper already has the order data and lets the buyer inspect
   goods [bca-shipper-2025-05].

### 4.2 Benign categories with count targets

| `benign_category` | Full name and definition | Resembles | Scored target |
|---|---|---|---:|
| `bank_notice_legitimate` | Real bank messages: OTP sent to the user with a "do not share" warning, balance-change notice, card expiry notice, reminder to update biometrics **inside the official app or at a branch**, official domain links | `bank_impersonation` | 10 |
| `government_notice_legitimate` | Real public-service contact: ward police ask the user to come to the office; tax or social-insurance reminders that point to the official portal or the App Store app; no link to an unknown domain | `government_service_impersonation`, `authority_impersonation` | 6 |
| `utility_telecom_legitimate` | Real power or telecom messages: bill reminder that names official payment channels, planned outage notice, data-plan offer by the operator's short code | `utility_telecom_impersonation` | 6 |
| `relative_money_request_consistent` | A relative or friend asks for money, and the text shows consistency: shared specific history, recipient account in the person's own name or a known account, a voice call or a meeting is offered or done, no secrecy | `account_takeover_money_request` | 12 |
| `real_emergency_contact` | A real school or relative reports an accident; the message gives the hospital name and asks the user to come or call the school; no transfer to a personal account | `relative_emergency` | 4 |
| `job_recruitment_legitimate` | A recruiter offers a job, asks for a CV, sets an interview; no fee, no deposit | `task_job_scam` | 8 |
| `investment_discussion_legitimate` | Friends or a licensed broker discuss savings, stocks or gold through licensed channels; no guaranteed return; no deposit to a personal account | `investment_romance_scam` | 6 |
| `friendship_dating_benign` | Friendly or romantic chat between people who met online; may last many messages; no money, no platform, no gift fees | `investment_romance_scam`, `parcel_customs_scam` | 8 |
| `promotion_lucky_draw_legitimate` | A real promotion or prize notice with an official domain, pickup at a store, or prize tax deducted by the organizer (not paid by the user to a personal account) | `prize_scam` | 6 |
| `lending_legitimate` | A bank loan officer asks the user to bring documents to a branch; or a friend lends money; no fee before disbursement | `loan_advance_fee` | 5 |
| `delivery_legitimate` | A shipper calls or messages about an order that the user placed; cash on delivery; inspection allowed; tracking through the official app | `delivery_shipper_scam` | 8 |
| `marketplace_booking_legitimate` | A buyer and a seller agree on goods; a hotel confirms a booking; payment through the platform or to the business account named on the official page | `online_purchase_booking_scam`, `fake_payment_wrong_transfer` | 8 |
| `payment_between_friends` | Bill splitting, repaying a small debt, a real mistaken transfer returned through the bank's official dispute process | `fake_payment_wrong_transfer` | 6 |
| `scam_discussion_warning` | People discuss a scam they heard of, forward a police warning, or ask each other "is this a scam?" about a third party; the conversation itself contains no attempt | Any (keywords such as "lừa đảo", "OTP", "công an") | 7 |
| `everyday_chat` | Ordinary family, school, work or neighborhood chat with no sensitive request | None (easy negatives) | 10 |
| **Total** | | | **110** |

Hard negatives (all categories except `everyday_chat`) are 100 of 110 scored benign conversations.

### 4.3 Paired near-miss construction

For each scam type with a target of 5 or more, the author writes at least two benign conversations that share the
scam type's channel and opening (for example, the same bank, the same "con bị tai nạn" opening, the same job
offer), and differ only in the facts that decide legitimacy. The `paired_with` field links them. This construction
tests whether a system detects the deciding evidence or only the topic.

---

## 5. Turn-level rule: the alert turn

### 5.1 The reference reader

The **careful, informed reader** is the reference for every turn-level decision:

- The reader sees only the prefix up to index t. The reader does not know the label or the later messages.
- The reader knows the public warnings in Section 3 and the legitimate procedures in Section 4.1.
- The reader cannot phone anyone or open links. The reader can use only the chat text, including reports in the
  chat about calls and verification ("mình vừa gọi cho mẹ rồi").
- The reader alerts when a scam is **more probable than benign and the cost of a wrong alert is acceptable**. The
  reader does not wait for certainty, and does not alert on a topic alone.

### 5.2 Evidence classes

Every evidence item has one class. Use these exact identifiers in the `evidence[].kind` field.

**Harmful requests** (the action that causes loss if the claim is false):

| `kind` | Definition |
|---|---|
| `request_money_transfer` | Request to transfer, deposit, pay a fee, tax, fine or deposit, or to buy gift cards or crypto |
| `request_credentials_or_otp` | Request for an OTP, password, PIN, CVV, full card number, or a login code for Zalo, Telegram or Facebook |
| `request_app_install_or_remote_access` | Request to install an app from a link or file (APK), or a screen-sharing or remote-control app |
| `request_link_with_data_entry` | Link that leads to a form for login, card data or personal data |
| `request_identity_documents_or_biometrics` | Request for citizen-ID photos, a face video, a "look at the camera" step, household data |
| `request_qr_scan_login` | Request to scan a QR code that logs in or links an account |

**Illegitimacy indicators** (facts that contradict the legitimate procedure of the claimed party):

| `kind` | Definition |
|---|---|
| `authority_outside_procedure` | A claimed police, court, tax, ward, power or bank actor does something that the official sources say it does not do by phone or chat (asks money to "verify", sends an app link, asks OTP) |
| `lookalike_or_unofficial_domain` | A link that imitates a brand or agency but is not its official domain (for example `vietcombank-diemthuong.com`), or an IP address or a URL shortener presented as an official link |
| `recipient_mismatch` | The recipient account name does not match the claimed person or organization, or the claimed organization asks for payment to a personal account |
| `advance_fee` | The user must pay before receiving a loan, prize, parcel, salary, commission, refund or recovered money |
| `unrealistic_gain` | Guaranteed or very high returns, pay far above market for trivial tasks, price far below market |
| `secrecy_or_isolation` | Demand to keep the matter secret, not to tell family or the bank, or to stay on the call |
| `verification_refused` | The contact refuses or avoids a voice call, a meeting, or verification through an official channel; or a video call is very short and of poor quality and is offered as proof |
| `identity_inconsistency` | The contact's facts, style or knowledge contradict the earlier history or the claimed identity |
| `threat_or_coercion` | Threat of arrest, prosecution, account lock, service cut, or public shaming |
| `escalating_payment` | A new fee or a larger deposit after an earlier payment, a "system error", or a "frozen account" |
| `unsolicited_claim` | A parcel, order, debt, prize or "mistaken transfer" that the user did not expect or cannot confirm |

`urgency` is recorded only as a supporting note in `alert_rationale`. Urgency alone is never an indicator, because
real emergencies are urgent too.

### 5.3 The alert condition

**Self-sufficient evidence.** One message is enough when it contains one of these items:

1. A counterpart request for an OTP, password, PIN or CVV (`request_credentials_or_otp`). No legitimate party
   asks the user to give these in a chat [vcb-reward-points-2026].
2. A claimed authority, bank or utility that asks to install an app from a link, or to transfer money to "verify",
   "protect" or "settle" a case (`request_app_install_or_remote_access` or `request_money_transfer`, with
   `authority_outside_procedure`).
3. A link to a lookalike domain of a brand or agency that asks for login, card or personal data
   (`request_link_with_data_entry` with `lookalike_or_unofficial_domain`).
4. An advance fee to receive money or a service that the contact promised (`request_money_transfer` with
   `advance_fee`).

**Combined evidence.** Otherwise, the alert condition holds at the first prefix that contains **at least one
harmful request and at least one illegitimacy indicator** that refer to the same scheme. The two items can be in
different messages.

**Definition of `alert_turn`.** `alert_turn` is the smallest message index t such that the alert condition holds for
the prefix 0..t. It is the index of the message that **completes** the condition.

- The completing message can be a user message. Example: the user writes "họ bảo em cài app này để nhận hoàn tiền",
  which reports a harmful request from an off-chat call.
- The condition is monotone: when it holds at t, it holds at every later index.
- Later messages do not move `alert_turn` earlier or later.
- In a scam conversation, `alert_turn` is never `null`. In a benign conversation, it is always `null`.

### 5.4 What does not suffice alone

These items do not complete the alert condition by themselves. The reader needs a harmful request and an
illegitimacy indicator, or a self-sufficient item.

| Item | Reason |
|---|---|
| An unknown contact, a greeting, a friend request | Most new contacts are legitimate |
| A link to an official domain (`vietcombank.com.vn`, `gdt.gov.vn`) | Legitimate organizations send links |
| An OTP message sent **to** the user, with no request to share it | That is the legitimate procedure |
| Mention of the police, a bank, a tax office, a court | Topic, not evidence |
| Urgency, emotion, a sad story | Real emergencies are urgent |
| A request for money from a contact whose identity and history are consistent, and who offers a call or uses their own account | That is a `relative_money_request_consistent` pattern |
| A job offer without a fee; a CV request | Legitimate recruitment |
| Talk about investment or crypto without a deposit request to an unlicensed platform | Discussion is legal |
| A romantic or friendly relationship, even a fast one | Many online relationships are real |
| The user's own suspicion ("có phải lừa đảo không?") | The user can be wrong; the reader judges the evidence |
| Spelling errors, no diacritics, teencode | Normal in Vietnamese chat |
| A scam keyword quoted in a warning or discussion | See `scam_discussion_warning` |

### 5.5 Tie-breaking rules for labelers

1. If two messages could each complete the condition, choose the **earlier** message.
2. If a harmful request is vague ("chị chuyển giúp em ít tiền nhé") and the illegitimacy indicator comes later,
   `alert_turn` is the index of the indicator.
3. If the harmful request and the indicator are in one message, that message is `alert_turn`.
4. A scam conversation in which the condition first holds at the last message is allowed, but the author keeps this
   case to at most 30 % of scam conversations (Section 7.4).
5. If a labeler cannot place `alert_turn` within ±2 messages with confidence, the labeler sets
   `ambiguity_flag: true` and writes the reason.

### 5.6 Evidence message indices

The optional field `evidence` lists every message that holds evidence under Section 5.2, not only the completing
message. Each item has a `message_index` and one or more `kind` values. The completing message at `alert_turn`
MUST be in the list. Evidence after `alert_turn` (for example an escalating payment) is listed too; it supports error
analysis but does not change `alert_turn`.

### 5.7 Illustrative examples

*Illustrative only — excluded from the test set.*

**Example A: single-message alert (`bank_impersonation`).**

| Index | Role | Text |
|---:|---|---|
| 0 | contact | "VCB: Diem thuong cua Quy khach se het han 30/10. Dang nhap va nhap thong tin the tai https://vcb-diemthuong.top de doi qua." |
| 1 | user | "link nay that ko vay" |

`alert_turn` = 0. Self-sufficient item 3: a link to a lookalike domain (not `vietcombank.com.vn`) with a request to
log in and enter card data.

**Example B: combined evidence across messages (`account_takeover_money_request`).**

| Index | Role | Text |
|---:|---|---|
| 0 | contact | "Tú ơi, đang bận không em" |
| 1 | user | "dạ không anh, có gì không ạ" |
| 2 | contact | "Anh đang kẹt chút việc, em chuyển giúp anh 15 triệu, tối anh gửi lại" |
| 3 | user | "Dạ để em gọi anh chút" |
| 4 | contact | "Anh đang họp không nghe máy được, em chuyển vào tài khoản này nhé: NGUYEN THI HOA – 0123456789" |

`alert_turn` = 4. Index 2 is a harmful request (`request_money_transfer`) but has no indicator. Index 4 adds
`verification_refused` and `recipient_mismatch` (the claimed sender is a man named in the history; the recipient is
a different person).

**Example C: hard negative (`relative_money_request_consistent`).** The same opening as Example B, but at index 4 the
contact says "Ừ gọi đi" and index 5 is the user's note "Ok em vừa nói chuyện với anh rồi, em chuyển vào TK của anh
nhé". `alert_turn` = `null`.

---

## 6. Data format and metadata schema

### 6.1 Principles

- One JSON object per conversation, in a JSON Lines file (Section 9).
- The object has two parts: **`input`** (what the engine may see) and **`gold`** plus **`provenance`** (what the
  engine must never see). The evaluation harness passes only `input` to the engine.
- This field table is the authoritative schema for version 1. A machine-readable JSON Schema is generated from it at
  generation time and checked against it.

### 6.2 Conversation object

| Field | Type | Required | Constraints and meaning |
|---|---|---|---|
| `id` | string | yes | `syn-v1-` + 4-digit number, for example `syn-v1-0042`. Assigned after a random shuffle, so the number carries no label information |
| `schema_version` | string | yes | `"1.0"` |
| `input.channel` | enum | yes | `zalo`, `messenger`, `sms`, `telegram` |
| `input.contact.display_name` | string | yes | Name as the user's app shows it. For SMS, a phone number or a brandname such as `"VCB"` |
| `input.contact.is_saved_contact` | boolean | yes | `true` if the contact is in the user's address book or friend list |
| `input.messages` | array of message | yes | Length 2 to 60. See 6.3 |
| `gold.label` | enum | yes | `scam`, `benign` |
| `gold.scam_type` | enum or null | yes | A Section 3.3 identifier if `label` = `scam`, otherwise `null` |
| `gold.benign_category` | enum or null | yes | A Section 4.2 identifier if `label` = `benign`, otherwise `null` |
| `gold.resembles_scam_type` | enum or null | yes | For a hard negative, the scam type it imitates; otherwise `null` |
| `gold.alert_turn` | integer or null | yes | 0-based message index under Section 5.3. `null` if and only if `label` = `benign` |
| `gold.evidence` | array of `{message_index: int, kind: [string]}` | yes for `scam`, empty for `benign` | Section 5.6. `kind` values from Section 5.2 |
| `gold.alert_rationale` | string | yes | One to three English sentences that name the clause of Section 5.3 (or, for benign, the consistency evidence of Section 5.4) |
| `gold.difficulty` | enum | yes | `easy`, `medium`, `hard` (6.5) |
| `gold.paired_with` | string or null | no | `id` of the near-miss twin (Section 4.3) |
| `provenance.seed` | object | yes | Section 6.4 |
| `provenance.generator.model` | string | yes | Exact model identifier, for example `claude-opus-5-5` |
| `provenance.generator.prompt_template_id` | string | yes | Name of the generation template, for example `scam-conversation-template-2026-10-23` |
| `provenance.generator.run_id` | string | yes | Name of the generation run, by purpose and date |
| `provenance.created` | string | yes | ISO date, for example `2026-10-23` |
| `provenance.guide_version` | string | yes | Version of this guide, for example `1.0` |
| `features.n_messages` | integer | yes | Equals the length of `input.messages` |
| `features.length_bucket` | enum | yes | `short` (2–5), `medium` (6–15), `long` (16–60) |
| `features.slow_build` | boolean | yes | `true` if `label` = `scam` and `alert_turn` ≥ 10 |
| `features.has_prior_benign_history` | boolean | yes | `true` if a scam starts after at least 6 benign messages with the same contact |
| `features.region` | enum | yes | `north`, `central`, `south`, `neutral` (vocabulary and particles, not accent) |
| `features.register` | enum | yes | `formal`, `casual`, `elderly_user`, `youth` |
| `features.diacritics` | enum | yes | `full`, `none`, `mixed` |
| `features.obfuscation` | array of enum | yes | Empty, or values from `teencode`, `spacing`, `homoglyph`, `digit_substitution`, `emoji_insertion`, `url_shortener` |
| `features.user_response` | enum | yes | `complies`, `refuses`, `verifies`, `ignores`, `mixed`, `not_applicable` |

Fields under `features` describe surface properties for coverage checks and per-slice analysis. They are not gold
labels, but they are also never passed to the engine.

### 6.3 Message object

| Field | Type | Required | Constraints and meaning |
|---|---|---|---|
| `index` | integer | yes | 0-based; equals the position in the array |
| `role` | enum | yes | `user` or `contact` |
| `text` | string | yes | The message text, possibly empty if the message is only an attachment. Unicode NFC |
| `timestamp` | string | no | ISO 8601 with `+07:00` offset. If any message has a timestamp, all messages have one, and they do not decrease |
| `attachments` | array | no | Objects with `type` and type-specific fields (below) |

Attachment placeholder types:

| `type` | Fields | Example meaning |
|---|---|---|
| `link` | `url` | A link preview; the URL also appears in `text` when the sender typed it |
| `image` | `description` (Vietnamese or English, what a viewer sees) | "Ảnh chụp lệnh bắt tạm giam có con dấu đỏ" |
| `file` | `filename`, `description` | `"VNeID_capnhat.apk"` |
| `voice` | `transcript`, `duration_s` | A voice message, given as its transcript |
| `call` | `kind` (`voice` or `video`), `duration_s`, `status` (`answered`, `missed`, `declined`), `description` | A call event inside the chat app; a video call description can say "hình mờ, giật, 8 giây" |
| `qr` | `description` | A QR code and what it claims to do |
| `contact_card` | `name`, `phone` | A shared contact card |
| `bank_transfer_receipt` | `description` | A screenshot of a transfer receipt |

### 6.4 Seed record

| Field | Type | Required | Meaning |
|---|---|---|---|
| `seed.kind` | enum | yes | `reported_case` (scam), `official_procedure` (benign that imitates an organization), `everyday_scenario` (other benign) |
| `seed.seed_id` | string | yes | Key into `seeds/seed_catalog.jsonl` |
| `seed.sources` | array of `{url, publisher, published, accessed, access_mode}` | yes for `reported_case` and `official_procedure` | `access_mode` is `fetched` or `search_summary` |
| `seed.case_facts.scam_type` | enum | for `reported_case` | Section 3.3 identifier |
| `seed.case_facts.impersonated_party` | string | for `reported_case` | For example "ward police officer" |
| `seed.case_facts.channel` | string | for `reported_case` | The channel in the report (may differ from `input.channel`) |
| `seed.case_facts.lure` | string | for `reported_case` | For example "administrative reorganization" |
| `seed.case_facts.requested_action` | string | for `reported_case` | For example "install fake VNeID app from a link" |
| `seed.case_facts.payment_method` | string | for `reported_case` | For example "bank account drained after device takeover" |
| `seed.case_facts.other` | string | no | Other case-level facts (amounts, platform names) |

Seed facts are **case-level facts only**. The seed record never contains message text from the source.

### 6.5 Difficulty

| Value | Scam conversation | Benign conversation |
|---|---|---|
| `easy` | A self-sufficient item, stated explicitly, in a short conversation | No surface feature of any scam type (`everyday_chat`) |
| `medium` | Combined evidence across two or more messages, or a mild obfuscation | A hard negative with one scam-like surface feature |
| `hard` | Slow-build (`alert_turn` ≥ 10), prior benign history, indirect requests, or obfuscation of the key evidence | A paired near-miss (Section 4.3), or a hard negative with two or more scam-like surface features |

---

## 7. Coverage and diversity targets

### 7.1 Totals

| Set | Scored target | Generation target |
|---|---:|---:|
| Scam | 110 | 125 |
| Benign | 110 | 125 |

The generation target is about 115 % of the scored target. Basis: COVA-X reported that 3.9 % of conversations still
needed relabeling after its cleanup [cova-x-2026], and this set adds an independent-agreement filter; the margin is
an operational allowance, not a measured exclusion rate. If exclusions leave a type below its scored target, the
author generates replacements under the same guide version **before** freezing.

Scam and benign distributions by type and category are in Sections 3.3 and 4.2.

### 7.2 Channel

| Channel | Scam | Benign |
|---|---:|---:|
| `zalo` | 45 | 45 |
| `messenger` | 25 | 25 |
| `sms` | 30 | 30 |
| `telegram` | 10 | 10 |

The channel distributions match between classes, so the channel is not a label cue.

### 7.3 Length

| `length_bucket` | Scam | Benign |
|---|---:|---:|
| `short` (2–5 messages) | 25 | 25 |
| `medium` (6–15 messages) | 55 | 55 |
| `long` (16–60 messages) | 30 | 30 |

The length distributions match between classes. The author also checks that the mean number of messages per class
differs by less than 15 %.

### 7.4 Alert position (scam conversations)

| Condition | Target |
|---|---|
| `alert_turn` = 0 (single-message alert) | 10 to 15 |
| `slow_build` (`alert_turn` ≥ 10) | at least 20 |
| `has_prior_benign_history` | at least 8 (mainly `account_takeover_money_request`) |
| At least 2 messages after `alert_turn` | at least 70 % of scam conversations |
| `alert_turn` at the last message | at most 30 % of scam conversations |

Benign long conversations (16 or more messages) are at least 30, so that false alerts late in long histories are
measurable.

### 7.5 Language variety

| Property | Target share in each class |
|---|---|
| `region` | `north` 35 %, `south` 35 %, `central` 15 %, `neutral` 15 % |
| `register` | each of `formal`, `casual`, `elderly_user`, `youth` at least 15 % |
| `diacritics` = `none` or `mixed` | 25 % to 35 % (SMS mostly) |
| Any `obfuscation` | 10 % to 20 % of each class |

**Symmetry rule.** No-diacritic text, teencode, spacing tricks and emoji appear in both classes at similar rates.
Homoglyph and digit substitution inside URLs or brand names are scam-specific in real reports, so they appear in
scam conversations; benign conversations include about 5 legitimate shortened or unusual-but-official URLs, so that
an unusual URL alone is not a label cue.

### 7.6 User behavior

In scam conversations, `user_response` covers `complies`, `refuses`, `verifies` and `mixed`, each at least 15 %.
The user states suspicion before `alert_turn` in at most 15 % of scam conversations. The user states suspicion in at
least 5 benign conversations (a wrong suspicion), so that the user's suspicion is not a label cue.

### 7.7 Authoring constraints that protect the labels

1. The author writes all text newly. The author never copies message text, phone numbers, account numbers or names
   from a source.
2. Names, phone numbers, account numbers and lookalike domains are fabricated. Real official domains and published
   hotlines MAY appear in benign conversations and as the imitated brand in scam conversations.
3. No stage directions, narration or English meta-text inside `text` (COVA-X reports "stage-direction bleed" as a
   generation failure [cova-x-2026]).
4. The generation prompt states what to write, not long lists of forbidden phrases. COVA-X reports that listing
   prohibited patterns increased them (salience bias) [cova-x-2026].
5. One generation call writes one conversation from one seed record, to reduce contamination across types (a
   failure reported by [cova-x-2026]).
6. Words such as "lừa đảo" or "scam" do not appear in scam conversations unless a character says them in a natural
   way. They appear in `scam_discussion_warning` benign conversations.

---

## 8. Quality-control procedure

### 8.1 First labels

The author records the intended labels (`gold.*`) when writing each conversation. These are the **author labels**.

### 8.2 Independent second pass

- A separate subagent, the **second labeler**, receives this guide and only the `input` part of each conversation,
  in a new random order. It does not see `gold`, `provenance`, `features`, the generation prompts, or the
  detection system.
- For each conversation it writes `label`, `scam_type` or `benign_category`, `alert_turn`, `evidence`,
  `ambiguity_flag` and a short rationale.
- The second labeler is a Claude model, because the detection model (Gemini) must not label test content. The two
  labels are therefore not fully independent (Section 10).

### 8.3 Agreement measures

**Conversation label: Cohen's kappa.** Cohen's kappa corrects observed agreement for agreement expected by chance
[artstein-poesio-2008]:

$$\kappa = \frac{p_o - p_e}{1 - p_e}$$

**New symbols**
- $p_o$: proportion of conversations on which the author label and the second label agree.
- $p_e$: proportion of agreement expected by chance from each labeler's marginal label rates.

**Alert turn.** On conversations that both labelers label `scam`, report:

- exact agreement rate ($a_0$): share with identical `alert_turn`;
- agreement within ±k messages ($a_1$, $a_2$) for k = 1 and k = 2;
- mean absolute difference in messages.

**Type agreement.** Agreement rate on `scam_type` and on `benign_category`, reported for information.

**Acceptance values** (owner decision, 2026-10-22, provisional): κ ≥ 0.80 on the conversation label, and
$a_1$ ≥ 0.80 on the alert turn. These are owner-chosen acceptance criteria. The value 0.80 is often attributed to
the agreement literature, but no source for it was verified: on 2026-10-22 the text of [artstein-poesio-2008]
could not be extracted (custom-encoded PDF, no PDF text tool installed; the publisher page returned HTTP 403).
If a value is lower, the guide is unclear or the conversations are not decidable from the
text. The author then revises the guide or the conversations, increments the guide version, and repeats the second
pass on all affected conversations before freezing.

### 8.4 Disagreement resolution

1. **Conversation-label disagreement or `ambiguity_flag`.** A third subagent, the **adjudicator**, reads the guide,
   the `input` part and both rationales, and decides by citing a specific clause of this guide. If no clause
   decides the case, the conversation goes to `excluded.jsonl` with reason `ambiguous_label`.
2. **Alert-turn difference of 1 or 2 messages.** The adjudicator applies Section 5.5. The adjudicated value becomes
   gold.
3. **Alert-turn difference of 3 or more messages.** The adjudicator decides by clause, or excludes with reason
   `ambiguous_alert_turn`.
4. **Systematic disagreement.** If three or more disagreements have the same cause, the cause is a guide defect.
   The author fixes the guide, increments the version, and re-checks every conversation that the change affects.
5. Every decision is recorded in `qc/adjudication.jsonl` with the clause cited. The author labels are kept unchanged
   in the record of the second pass; only the frozen `gold` holds the final values.

### 8.5 Automatic checks (all must pass before freezing)

| Check | Rule |
|---|---|
| Schema | Every object matches Section 6. `alert_turn` is `null` if and only if `label` = `benign`. `alert_turn` < `n_messages`. Every `evidence.message_index` < `n_messages`. `alert_turn` is in `evidence` |
| Exact duplicates | SHA-256 of the normalized message texts (NFC, lower case, whitespace collapsed) is unique |
| Near duplicates | Character 5-gram Jaccard similarity between any two conversations < 0.6; pairs above are reviewed and one is rewritten or removed. Paired near-misses (Section 4.3) are reviewed but allowed |
| Source copying | No 8-word sequence of any fetched source page text appears in a conversation (checked when the source text is available) |
| Meta-text | No English narration, no bracketed stage directions, no words "scam", "label", "benign" in `text` |
| Coverage | Section 7 targets met within ±1 conversation per cell |
| Label-cue balance | Class means of message count, characters per message and share of messages with links are reported; a large difference is reviewed |
| Personal data | No real person's name, phone number or account number from any source |

### 8.6 Human spot check

Owner decision, 2026-10-22: do a human spot check of 20 randomly sampled scored conversations **if a suitable person
is available**. The person must not work on the detection system (neither the owner nor the assistant), because the
developer context must not see test content. The person labels the `input` part blind, using this guide. The result
(agreement with gold, and every disagreement with its reason) is recorded in `qc/human_spot_check.jsonl` and
summarized in `qc_report.json`. If no person is available at freeze time, the manifest records the spot check as
not done; it is not reported as passed.

---

## 9. Freezing procedure

### 9.1 File layout

```
testset/
├── LABELING_GUIDE.md                 # this guide; its SHA-256 goes into each manifest
├── CHANGELOG.md                      # one entry per test-set version
├── seeds/
│   └── seed_catalog.jsonl            # case-level facts and source URLs; written before generation
├── synthetic-v1/
│   ├── conversations.jsonl           # the frozen scored set
│   ├── excluded.jsonl                # unscored: ambiguous or failed QC, with reasons
│   ├── qc/
│   │   ├── second_pass.jsonl
│   │   ├── adjudication.jsonl
│   │   └── qc_report.json            # kappa, alert-turn agreement, coverage, check results
│   ├── manifest.json                 # counts, versions, hashes, generator, dates
│   └── SHA256SUMS                    # sha256sum format, one line per file in this folder and in seeds/
└── case-studies-real/                # optional, separate, never pooled with synthetic-v1
```

The development set lives outside `testset/`, in `devset/` (Section 11), so that the held-out boundary is a
directory boundary.

**Version control** (owner decision, 2026-10-22). This guide is committed to the local branch. Whether the test
conversations, seeds and QC files go into git is decided at freeze time. Nothing is pushed to the public remote
without the owner's explicit approval.

### 9.2 Canonical serialization

- Encoding UTF-8, no byte-order mark. Line ending `\n`. The file ends with one `\n`.
- One conversation per line. Lines are sorted by `id` in ascending order.
- Each line is produced as `json.dumps(obj, ensure_ascii=False, sort_keys=True, separators=(",", ":"))`.
- All strings are Unicode NFC. Homoglyph obfuscation uses distinct code points (for example Cyrillic `а`), which NFC
  keeps.
- Numbers are integers. No floating-point values in conversation records.

### 9.3 Manifest

`manifest.json` holds: test-set version (`synthetic-v1`), freeze date, guide version and guide SHA-256, generator
model identifiers, prompt template identifiers, counts per class, type and category, number of excluded
conversations per reason, QC agreement values, the SHA-256 of `conversations.jsonl`, and a per-record SHA-256 of each
canonical line (so a single changed record is traceable).

### 9.4 Freeze steps

1. All checks in Section 8.5 pass, and the QC values meet the acceptance values that the owner confirms.
2. Write the canonical files, then `manifest.json`, then `SHA256SUMS`.
3. Verify with `sha256sum -c SHA256SUMS`.
4. Remove write permission from the frozen files (`chmod a-w`).
5. Report the SHA-256 of `conversations.jsonl` to the project owner, who records it in the project state files.
   This step happens **before** any detection run reads the set.

### 9.5 Rules after freezing

- A frozen file is never edited.
- A correction creates a new version (`synthetic-v2/`) with its own manifest and hashes. `CHANGELOG.md` lists each
  changed or removed `id`, the reason, and the guide clause.
- Every reported result names the test-set version and its SHA-256.
- Results on different versions are not pooled.
- The evaluation harness reads the frozen file, passes only `input` to the engine, and outputs aggregate metrics.
  Per-conversation outputs stay outside the developer context.

---

## 10. Known limitations

1. **Single-generator style bias.** One model family (OpenAI, through Codex) writes all conversations. Its phrasing, rhythm and
   choice of details are more uniform than real chat. A detector can learn or benefit from these regularities. The
   set measures detection of **these written patterns**, not of real messages.
2. **Correlated labeling.** The author (OpenAI) and the second labeler (Claude) are different model families, but
   both are large language models trained on similar web text. Agreement between them can still overestimate
   agreement between independent humans. A human spot check (Section 8.6) reduces but does not remove
   this risk.
3. **No prevalence information.** The class balance (about 1:1) and the type counts are design choices. Precision on
   this set does not predict precision on real traffic, where most conversations are benign. Report a
   precision estimate at a stated assumed prevalence only as a scenario, not as a measurement.
4. **Seed bias toward reported cases.** Seeds come from police warnings and news reports. These sources describe
   scams that were already noticed, often with large losses. New or quiet patterns are under-represented.
5. **Old and secondary sources.** Several anchor sources are from 2023, and most are news reports of official
   warnings rather than the official documents. Some facts are from fetch-tool summaries or search summaries
   (Section 3.4). The author did not read every original page in full.
6. **Exclusion of ambiguous cases.** The scored set omits the cases that are hardest even for humans (Section 2.3),
   so it can overestimate real-world accuracy.
7. **Text-only and one-to-one.** Images, audio, real video calls, group chats and cross-app journeys appear only as
   text placeholders or not at all. Many real scams start with a voice call; this set represents the call only by
   placeholders and by what the chat says about it.
8. **Turn-level gold is a judgment.** `alert_turn` follows the rule of Section 5, which is a reasoned standard, not an
   observed behavior of real users. PreScam derives its boundary with a model-based threshold instead
   [prescam-2026]; results on the two kinds of boundary are not directly comparable.
9. **Language coverage.** Regional variety is represented by vocabulary and particles in writing. It does not cover
   ethnic-minority languages or the full range of informal spelling.
10. **Public guide.** If the detection developers read this guide, the system can be designed toward its evidence
    classes. The test still holds out the conversations, but the score then partly measures agreement with this
    guide's definition of evidence. This is acceptable only if the owner treats the guide as the task contract.

---

## 11. Development set

Owner decision, 2026-10-22: build a separate development set that the detection developers MAY read, to debug
prompts and tools without touching the test set.

| Property | Rule |
|---|---|
| Location | `devset/` at the repository root: `devset/seeds/seed_catalog.jsonl`, `devset/conversations.jsonl`, `devset/qc/`, `devset/manifest.json`, `devset/SHA256SUMS` |
| Guide | This guide; same schema (Section 6) with `id` prefix `dev-v1-` |
| Size | 30 scam and 30 benign conversations. Every scam type in Section 3.3 and every benign category in Section 4.2 has at least one conversation |
| Seeds | Seed cases are **disjoint** from the test seed cases: no `seed_id` and no source report is shared. The seed collector assigns each collected case to exactly one set before any generation |
| Order | The test set is generated and frozen first. The development set is generated after the freeze, so that no development-set content can influence the test set |
| Quality control | The automatic checks of Section 8.5 and the second pass of Section 8.2. Agreement values are reported; they are not a freeze gate |
| Use | Development, debugging, prompt and tool design, few-shot examples. **Not** a substitute for the test set in any reported result |
| Training | Not used to train or fine-tune a model unless the owner decides so; a training-data decision is separate |
| Freeze | Hashed with `SHA256SUMS` like the test set, so that results on it are traceable; a new version may be made at any time |

Limitation: the development set comes from the same generator, guide and kind of sources as the test set. A system
tuned on it can learn generator-specific regularities that also appear in the test set (Section 10, item 1).

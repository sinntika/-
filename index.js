require('dotenv').config();

const crypto = require('crypto');

const {
  Client,
  GatewayIntentBits,
  Events,
  PermissionFlagsBits,
  ActionRowBuilder,
  ButtonBuilder,
  ButtonStyle,
  EmbedBuilder,
  ModalBuilder,
  TextInputBuilder,
  TextInputStyle,
  ChannelType
} = require('discord.js');

// ============================================================
// 環境変数チェック
// ============================================================

const requiredEnv = [
  'DISCORD_TOKEN',
  'DISCORD_CLIENT_ID',
  'VERIFY_BASE_URL',
  'API_BASE_URL',
  'VERIFY_TOKEN_SECRET',
  'INTERNAL_API_TOKEN'
];

for (const key of requiredEnv) {
  if (!process.env[key] || process.env[key].trim() === '') {
    console.error(`❌ 必須環境変数が未設定です: ${key}`);
    process.exit(1);
  }
}

const VERIFY_TOKEN_TTL_SEC = Number(process.env.VERIFY_TOKEN_TTL_SEC || 300);
const POLL_INTERVAL_MS     = Number(process.env.POLL_INTERVAL_MS || 5000);

// ============================================================
// ギルド設定キャッシュ (DBから取得した設定を一時保存)
// guild_id → config オブジェクト
// ============================================================

/** @type {Map<string, object|null>} */
const guildConfigCache = new Map();
const CACHE_TTL_MS = 60_000; // 1分キャッシュ
/** @type {Map<string, number>} */
const guildConfigCacheAt = new Map();

/**
 * DB (guild_settings.php) からサーバー設定を取得する。
 * 1分以内に取得済みならキャッシュを返す。
 * 未登録サーバーは null を返す。
 */
async function fetchGuildConfig(guildId) {
  const now = Date.now();
  const cachedAt = guildConfigCacheAt.get(guildId) ?? 0;

  if (guildConfigCache.has(guildId) && now - cachedAt < CACHE_TTL_MS) {
    return guildConfigCache.get(guildId);
  }

  try {
    const data = await apiGetJson('/guild_settings.php', { guild_id: guildId });
    const cfg  = data.config ?? null;
    guildConfigCache.set(guildId, cfg);
    guildConfigCacheAt.set(guildId, now);
    return cfg;
  } catch {
    // API エラー時は古いキャッシュを返す (あれば)
    return guildConfigCache.get(guildId) ?? null;
  }
}

/** キャッシュを強制削除して次回再取得させる */
function invalidateGuildConfig(guildId) {
  guildConfigCache.delete(guildId);
  guildConfigCacheAt.delete(guildId);
}

// ============================================================
// Discord Client
// ============================================================

const client = new Client({ intents: [GatewayIntentBits.Guilds] });

// ============================================================
// ボタン/モーダルのカスタムID定数
// ============================================================

const BTN_VERIFY            = 'ninsyou_verify_open';
const BTN_GAIKOU_PANEL      = 'ticket_gaikou_create';
const BTN_KOKUMIN_PANEL     = 'ticket_kokumin_create';
const BTN_SUPPORT_PANEL     = 'ticket_support_create';

const MODAL_GAIKOU          = 'ticket_gaikou_modal';
const MODAL_KOKUMIN         = 'ticket_kokumin_modal';
const MODAL_SUPPORT         = 'ticket_support_modal';

const INPUT_GAIKOU_COUNTRY  = 'ticket_gaikou_country_name';
const INPUT_KOKUMIN_MCID    = 'ticket_kokumin_mcid';
const INPUT_SUPPORT_REASON  = 'ticket_support_reason';

// ============================================================
// ユーティリティ
// ============================================================

function isAdmin(interaction, config) {
  const hasAdminPerm =
    interaction.memberPermissions?.has(PermissionFlagsBits.Administrator) ?? false;
  const adminRoleId = config?.admin_role_id?.trim() || '';

  if (!adminRoleId) return hasAdminPerm;
  return hasAdminPerm || (interaction.member?.roles?.cache?.has(adminRoleId) ?? false);
}

function base64UrlEncode(input) {
  return Buffer.from(input).toString('base64url');
}

function signVerifyToken(payload) {
  const body = base64UrlEncode(JSON.stringify(payload));
  const sig  = crypto
    .createHmac('sha256', process.env.VERIFY_TOKEN_SECRET)
    .update(body)
    .digest('base64url');
  return `${body}.${sig}`;
}

function createVerifyUrl(guildId, user) {
  const payload = {
    guildId,
    userId:      user.id,
    username:    user.username    || '',
    globalName:  user.globalName  || '',
    displayName: user.displayName || user.globalName || user.username || '',
    tag:         user.tag         || user.username   || '',
    exp:         Date.now() + VERIFY_TOKEN_TTL_SEC * 1000
  };
  const token = signVerifyToken(payload);
  const url   = new URL(process.env.VERIFY_BASE_URL);
  url.searchParams.set('token', token);
  return url.toString();
}

function statusLabel(status) {
  switch (status) {
    case 'approved':          return '✅ 認証成功';
    case 'blocked_country':   return '🌐 国制限によりブロック';
    case 'blocked_duplicate': return '🛡️ 重複IPによりブロック';
    case 'blocked_same_user': return '🚫 同じIDの再認証をブロック';
    case 'blocked_provider':  return '📡 プロバイダー判定によりブロック';
    default:                  return `❔ 不明: ${status || 'unknown'}`;
  }
}

function statusColor(status) {
  switch (status) {
    case 'approved':        return 0x2ecc71;
    case 'blocked_country': return 0xe67e22;
    default:                return 0xe74c3c;
  }
}

function trunc(text, max = 1000) {
  const s = String(text ?? '');
  return s.length <= max ? s : `${s.slice(0, max - 3)}...`;
}

function providerInfo(item) {
  return [
    `ISP: ${trunc(item.risk_isp || '不明', 120)}`,
    `組織: ${trunc(item.risk_organization || '不明', 120)}`,
    `ASN: ${trunc(item.risk_asn || '不明', 50)}`,
    `リスクスコア: ${item.risk_score ?? '不明'}`,
    `判定理由: ${trunc(item.risk_flags || 'なし', 180)}`
  ].join('\n');
}

function apiErrorJa(msg) {
  const m = String(msg || '');
  if (m.includes('forbidden')) {
    return [
      'API認証に失敗しました。',
      '`INTERNAL_API_TOKEN` と PHP側 `DISCORD_INTERNAL_API_TOKEN` が一致しているか確認してください。',
      '',
      '```bash',
      'curl -s -H "X-Internal-Token: $INTERNAL_API_TOKEN" ' + process.env.API_BASE_URL + '/pending.php',
      '```'
    ].join('\n');
  }
  if (m.includes('non-JSON') || m.includes('HTML')) {
    return 'APIからHTMLが返りました。`API_BASE_URL` またはPHP側のエラーを確認してください。';
  }
  return m;
}

function sanitizeName(text) {
  return String(text ?? '')
    .trim().toLowerCase()
    .replace(/\s+/g, '-')
    .replace(/[\\/#?:]/g, '')
    .replace(/[^a-z0-9ぁ-んァ-ヶ一-龠ー_-]/g, '')
    .replace(/-+/g, '-').replace(/^-|-$/g, '')
    .slice(0, 80);
}

// ============================================================
// API ヘルパー
// ============================================================

async function apiReq(path, options = {}) {
  const base = process.env.API_BASE_URL.replace(/\/+$/, '');
  const url  = `${base}${path.startsWith('/') ? path : '/' + path}`;

  const res  = await fetch(url, {
    ...options,
    headers: {
      Authorization:    `Bearer ${process.env.INTERNAL_API_TOKEN}`,
      'X-Internal-Token': process.env.INTERNAL_API_TOKEN,
      ...(options.headers || {})
    }
  });

  const raw = await res.text();
  let json;

  try {
    json = JSON.parse(raw);
  } catch {
    const ct = res.headers.get('content-type') || 'unknown';
    throw new Error(`API returned non-JSON. HTTP ${res.status}, CT: ${ct}, body: ${trunc(raw, 300)}`);
  }

  if (!res.ok || json.ok !== true) {
    throw new Error(json.error || `API error HTTP ${res.status}`);
  }

  return json;
}

async function apiGetJson(path, params = {}) {
  const q = new URLSearchParams(params).toString();
  return apiReq(q ? `${path}?${q}` : path, { method: 'GET' });
}

async function apiPostJson(path, body = {}) {
  return apiReq(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json; charset=utf-8' },
    body: JSON.stringify(body)
  });
}

// ============================================================
// ギルド設定をDBに保存
// ============================================================

async function saveGuildConfig(guildId, fields) {
  await apiPostJson('/guild_settings.php', { guild_id: guildId, ...fields });
  invalidateGuildConfig(guildId);
}

// ============================================================
// Embed ビルダー
// ============================================================

function embedVerifyPanel() {
  return new EmbedBuilder()
    .setColor(0x2ecc71)
    .setDescription('認証をするには↓のボタンを押してください');
}

function embedPrivateVerify(guildName) {
  return new EmbedBuilder()
    .setColor(0x3498db)
    .setTitle('🔐 認証リンク')
    .setDescription(
      `下のボタンを押して認証ページを開いてください。\n\nこのリンクの有効期限は **${VERIFY_TOKEN_TTL_SEC}秒** です。`
    )
    .addFields(
      { name: '対象サーバー', value: guildName || '不明', inline: true },
      { name: '状態',         value: '認証待ち',           inline: true }
    )
    .setFooter({ text: '認証BOT' }).setTimestamp();
}

// ============================================================
// チケット共通処理
// ============================================================

async function fetchCategory(guild, categoryId) {
  if (!categoryId) return null;
  const ch = await guild.channels.fetch(categoryId).catch(() => null);
  if (!ch || ch.type !== ChannelType.GuildCategory) return null;
  return ch;
}

async function findDupTicket(guild, categoryId, channelName) {
  const chs = await guild.channels.fetch().catch(() => null);
  if (!chs) return null;
  return chs.find(c => c && c.parentId === categoryId && c.name === channelName) || null;
}

function getCreatorId(channel) {
  const m = (channel?.topic || '').match(/creator_id=(\d+)/);
  return m ? m[1] : null;
}

// ---- 外交パネル ----
function embedGaikouPanel() {
  return new EmbedBuilder()
    .setColor(0x3498db).setTitle('外交申請用チケット')
    .setDescription('基本的に作成されたチケットにて外交を行います\n作成するには↓のボタンをクリックしてください')
    .setFooter({ text: 'チケットBOT' }).setTimestamp();
}

// ---- 国民申請パネル ----
function embedKokuminPanel() {
  return new EmbedBuilder()
    .setColor(0x2ecc71).setTitle('国民申請用チケット')
    .setDescription('国民申請するには↓のボタンを押してください')
    .setFooter({ text: 'チケットBOT' }).setTimestamp();
}

// ---- サポートパネル ----
function embedSupportPanel() {
  return new EmbedBuilder()
    .setColor(0x9b59b6).setTitle('サポートチケット')
    .setDescription('サポートが必要な場合は↓のボタンを押してチケットを作成してください')
    .setFooter({ text: 'チケットBOT' }).setTimestamp();
}

function btnRow(customId, label, style) {
  return new ActionRowBuilder().addComponents(
    new ButtonBuilder().setCustomId(customId).setLabel(label).setStyle(style)
  );
}

// ============================================================
// /setup コマンド処理
// ============================================================

async function handleSetup(interaction) {
  await interaction.deferReply({ ephemeral: true });

  const verifyRole  = interaction.options.getRole('verify_role', true);
  const logChannel  = interaction.options.getChannel('log_channel', true);
  const adminRole   = interaction.options.getRole('admin_role', false);

  // サーバー名を取得 (ログディレクトリ名に使う)
  const guildName = interaction.guild?.name || '';

  try {
    await saveGuildConfig(interaction.guildId, {
      guild_name:      guildName,
      verify_role_id:  verifyRole.id,
      log_channel_id:  logChannel.id,
      admin_role_id:   adminRole?.id || ''
    });
  } catch (err) {
    await interaction.editReply({
      embeds: [
        new EmbedBuilder().setColor(0xe74c3c).setTitle('❌ 設定の保存に失敗しました')
          .setDescription(trunc(apiErrorJa(err.message), 2000))
      ]
    });
    return;
  }

  await interaction.editReply({
    embeds: [
      new EmbedBuilder().setColor(0x2ecc71).setTitle('✅ 認証BOT設定を保存しました')
        .addFields(
          { name: 'サーバー名',     value: guildName || '(取得失敗)',               inline: false },
          { name: '認証ロール',     value: `${verifyRole}`,                         inline: true },
          { name: 'ログチャンネル', value: `${logChannel}`,                         inline: true },
          { name: '管理ロール',     value: adminRole ? `${adminRole}` : '(管理者権限のみ)', inline: true }
        )
        .setFooter({ text: 'IPログは accsess-ip/<サーバー名>/ に保存されます' }).setTimestamp()
    ]
  });
}

// ============================================================
// /setup-ticket コマンド処理
// ============================================================

async function handleSetupTicket(interaction) {
  await interaction.deferReply({ ephemeral: true });

  const gaikouCatRaw    = interaction.options.getString('gaikou_category_id');
  const gaikouMention   = interaction.options.getRole('gaikou_mention_role');
  const kokuminCatRaw   = interaction.options.getString('kokumin_category_id');
  const supportCatRaw   = interaction.options.getString('support_category_id');

  const toId = (raw) => {
    if (!raw) return undefined; // 未指定 → 既存値を維持
    if (raw.trim().toLowerCase() === 'none') return ''; // "none" → 無効化
    return raw.trim();
  };

  const fields = {};
  const v = toId(gaikouCatRaw);  if (v !== undefined) fields.gaikou_category_id      = v;
  if (gaikouMention)              fields.gaikou_mention_role_id = gaikouMention.id;
  const v2 = toId(kokuminCatRaw); if (v2 !== undefined) fields.kokumin_category_id   = v2;
  const v3 = toId(supportCatRaw); if (v3 !== undefined) fields.support_category_id   = v3;

  if (Object.keys(fields).length === 0) {
    await interaction.editReply({
      embeds: [
        new EmbedBuilder().setColor(0xf1c40f).setTitle('⚠️ 変更する項目がありません')
          .setDescription('少なくとも1つオプションを指定してください。')
      ]
    });
    return;
  }

  try {
    await saveGuildConfig(interaction.guildId, fields);
  } catch (err) {
    await interaction.editReply({
      embeds: [
        new EmbedBuilder().setColor(0xe74c3c).setTitle('❌ 設定の保存に失敗しました')
          .setDescription(trunc(apiErrorJa(err.message), 2000))
      ]
    });
    return;
  }

  // 保存後に最新設定を再取得して表示
  const cfg = await fetchGuildConfig(interaction.guildId);

  await interaction.editReply({
    embeds: [
      new EmbedBuilder().setColor(0x2ecc71).setTitle('✅ チケット設定を保存しました')
        .addFields(
          { name: '外交カテゴリID',    value: cfg?.gaikou_category_id      || '(未設定)', inline: true },
          { name: '外交メンションRole', value: cfg?.gaikou_mention_role_id  || '(未設定)', inline: true },
          { name: '国民申請カテゴリID', value: cfg?.kokumin_category_id     || '(未設定)', inline: true },
          { name: 'サポートカテゴリID', value: cfg?.support_category_id     || '(未設定)', inline: true }
        )
        .setFooter({ text: '設定はDBに保存されました' }).setTimestamp()
    ]
  });
}

// ============================================================
// /setup-show コマンド処理
// ============================================================

async function handleSetupShow(interaction) {
  await interaction.deferReply({ ephemeral: true });

  const cfg = await fetchGuildConfig(interaction.guildId);

  if (!cfg) {
    await interaction.editReply({
      embeds: [
        new EmbedBuilder().setColor(0xf1c40f).setTitle('⚠️ 設定が見つかりません')
          .setDescription('`/setup` コマンドで設定を登録してください。')
      ]
    });
    return;
  }

  await interaction.editReply({
    embeds: [
      new EmbedBuilder().setColor(0x3498db).setTitle('⚙️ 現在のBOT設定')
        .addFields(
          { name: '認証ロールID',       value: cfg.verify_role_id         || '(未設定)', inline: true },
          { name: 'ログチャンネルID',    value: cfg.log_channel_id          || '(未設定)', inline: true },
          { name: '管理ロールID',        value: cfg.admin_role_id           || '(管理者権限のみ)', inline: true },
          { name: '外交カテゴリID',      value: cfg.gaikou_category_id      || '(無効)', inline: true },
          { name: '外交メンションRole',  value: cfg.gaikou_mention_role_id  || '(未設定)', inline: true },
          { name: '国民申請カテゴリID',  value: cfg.kokumin_category_id     || '(無効)', inline: true },
          { name: 'サポートカテゴリID',  value: cfg.support_category_id     || '(無効)', inline: true },
          { name: '最終更新',            value: cfg.updated_at              || '不明',   inline: false }
        )
        .setFooter({ text: '認証BOT' }).setTimestamp()
    ]
  });
}

// ============================================================
// チケットパネル設置コマンド
// ============================================================

async function handleCreateGaikou(interaction, cfg) {
  if (!cfg?.gaikou_category_id) {
    await interaction.editReply({
      embeds: [new EmbedBuilder().setColor(0xe74c3c).setTitle('❌ チケット機能無効')
        .setDescription('`/setup-ticket` で外交カテゴリIDを設定してください。')]
    });
    return;
  }
  await interaction.channel.send({
    embeds: [embedGaikouPanel()],
    components: [btnRow(BTN_GAIKOU_PANEL, '作成', ButtonStyle.Primary)]
  });
  await interaction.editReply({
    embeds: [new EmbedBuilder().setColor(0x2ecc71).setTitle('✅ 外交申請パネルを設置しました')]
  });
}

async function handleCreateKokumin(interaction, cfg) {
  if (!cfg?.kokumin_category_id) {
    await interaction.editReply({
      embeds: [new EmbedBuilder().setColor(0xe74c3c).setTitle('❌ チケット機能無効')
        .setDescription('`/setup-ticket` で国民申請カテゴリIDを設定してください。')]
    });
    return;
  }
  await interaction.channel.send({
    embeds: [embedKokuminPanel()],
    components: [btnRow(BTN_KOKUMIN_PANEL, '作成', ButtonStyle.Success)]
  });
  await interaction.editReply({
    embeds: [new EmbedBuilder().setColor(0x2ecc71).setTitle('✅ 国民申請パネルを設置しました')]
  });
}

async function handleCreateSupport(interaction, cfg) {
  if (!cfg?.support_category_id) {
    await interaction.editReply({
      embeds: [new EmbedBuilder().setColor(0xe74c3c).setTitle('❌ チケット機能無効')
        .setDescription('`/setup-ticket` でサポートカテゴリIDを設定してください。')]
    });
    return;
  }
  await interaction.channel.send({
    embeds: [embedSupportPanel()],
    components: [btnRow(BTN_SUPPORT_PANEL, 'サポートを依頼する', ButtonStyle.Secondary)]
  });
  await interaction.editReply({
    embeds: [new EmbedBuilder().setColor(0x2ecc71).setTitle('✅ サポートチケットパネルを設置しました')]
  });
}

// ============================================================
// モーダル表示
// ============================================================

async function showGaikouModal(interaction) {
  const modal = new ModalBuilder().setCustomId(MODAL_GAIKOU).setTitle('外交申請');
  modal.addComponents(new ActionRowBuilder().addComponents(
    new TextInputBuilder().setCustomId(INPUT_GAIKOU_COUNTRY)
      .setLabel('あなたの国名は？').setStyle(TextInputStyle.Short).setRequired(true).setMaxLength(50)
  ));
  await interaction.showModal(modal);
}

async function showKokuminModal(interaction) {
  const modal = new ModalBuilder().setCustomId(MODAL_KOKUMIN).setTitle('国民申請');
  modal.addComponents(new ActionRowBuilder().addComponents(
    new TextInputBuilder().setCustomId(INPUT_KOKUMIN_MCID)
      .setLabel('あなたのMCIDは？').setStyle(TextInputStyle.Short).setRequired(true).setMaxLength(32)
  ));
  await interaction.showModal(modal);
}

async function showSupportModal(interaction) {
  const modal = new ModalBuilder().setCustomId(MODAL_SUPPORT).setTitle('サポートチケット');
  modal.addComponents(new ActionRowBuilder().addComponents(
    new TextInputBuilder().setCustomId(INPUT_SUPPORT_REASON)
      .setLabel('お問い合わせ内容 (任意)')
      .setStyle(TextInputStyle.Paragraph)
      .setRequired(false).setMaxLength(500)
  ));
  await interaction.showModal(modal);
}

// ============================================================
// チケット作成: 外交
// ============================================================

async function createGaikouTicket(interaction) {
  await interaction.deferReply({ ephemeral: true });

  const cfg = await fetchGuildConfig(interaction.guildId);

  if (!cfg?.gaikou_category_id) {
    await interaction.editReply({
      embeds: [new EmbedBuilder().setColor(0xe74c3c).setTitle('❌ チケット機能無効')]
    });
    return;
  }

  const guild          = interaction.guild;
  const countryNameRaw = interaction.fields.getTextInputValue(INPUT_GAIKOU_COUNTRY);
  const countryName    = sanitizeName(countryNameRaw);

  if (!countryName) {
    await interaction.editReply({
      embeds: [new EmbedBuilder().setColor(0xe74c3c).setTitle('❌ 国名が無効です')
        .setDescription('使える文字を含めて入力してください。')]
    });
    return;
  }

  const category = await fetchCategory(guild, cfg.gaikou_category_id);

  if (!category) {
    await interaction.editReply({
      embeds: [new EmbedBuilder().setColor(0xe74c3c).setTitle('❌ カテゴリーが見つかりません')
        .setDescription(`カテゴリID \`${cfg.gaikou_category_id}\` を確認してください。`)]
    });
    return;
  }

  const channelName = `${countryName}-外交`;
  const dup = await findDupTicket(guild, cfg.gaikou_category_id, channelName);

  if (dup) {
    await interaction.editReply({
      embeds: [new EmbedBuilder().setColor(0xf1c40f).setTitle('⚠️ 既に外交チケットがあります')
        .setDescription(`重複作成はできません。\n${dup}`)]
    });
    return;
  }

  const overwrites = [
    { id: guild.roles.everyone.id, deny: [PermissionFlagsBits.ViewChannel, PermissionFlagsBits.SendMessages, PermissionFlagsBits.ReadMessageHistory] },
    { id: interaction.user.id,     allow: [PermissionFlagsBits.ViewChannel, PermissionFlagsBits.SendMessages, PermissionFlagsBits.ReadMessageHistory, PermissionFlagsBits.AttachFiles, PermissionFlagsBits.EmbedLinks] }
  ];

  if (cfg.gaikou_mention_role_id) {
    overwrites.push({ id: cfg.gaikou_mention_role_id, allow: [PermissionFlagsBits.ViewChannel, PermissionFlagsBits.SendMessages, PermissionFlagsBits.ReadMessageHistory, PermissionFlagsBits.AttachFiles, PermissionFlagsBits.EmbedLinks] });
  }

  const ticketCh = await guild.channels.create({
    name: channelName,
    type: ChannelType.GuildText,
    parent: cfg.gaikou_category_id,
    topic: `ticket_type=gaikou | creator_id=${interaction.user.id} | country=${countryNameRaw}`,
    permissionOverwrites: overwrites,
    reason: `外交チケット: ${interaction.user.tag}`
  });

  const sendOpts = {
    embeds: [new EmbedBuilder().setColor(0x3498db)
      .setDescription('外交官が到着するまでお待ちください。\nご用件をお書きください。')
      .setFooter({ text: `作成者: ${interaction.user.tag}` }).setTimestamp()]
  };

  if (cfg.gaikou_mention_role_id) {
    sendOpts.content = `<@&${cfg.gaikou_mention_role_id}>`;
    sendOpts.allowedMentions = { roles: [cfg.gaikou_mention_role_id] };
  }

  await ticketCh.send(sendOpts);

  await interaction.editReply({
    embeds: [new EmbedBuilder().setColor(0x2ecc71).setTitle('✅ 外交チケットを作成しました')
      .setDescription(`${ticketCh}`)]
  });
}

// ============================================================
// チケット作成: 国民申請
// ============================================================

async function createKokuminTicket(interaction) {
  await interaction.deferReply({ ephemeral: true });

  const cfg = await fetchGuildConfig(interaction.guildId);

  if (!cfg?.kokumin_category_id) {
    await interaction.editReply({
      embeds: [new EmbedBuilder().setColor(0xe74c3c).setTitle('❌ チケット機能無効')]
    });
    return;
  }

  const guild   = interaction.guild;
  const mcidRaw = interaction.fields.getTextInputValue(INPUT_KOKUMIN_MCID);
  const mcid    = sanitizeName(mcidRaw);

  if (!mcid) {
    await interaction.editReply({
      embeds: [new EmbedBuilder().setColor(0xe74c3c).setTitle('❌ MCIDが無効です')]
    });
    return;
  }

  const category = await fetchCategory(guild, cfg.kokumin_category_id);

  if (!category) {
    await interaction.editReply({
      embeds: [new EmbedBuilder().setColor(0xe74c3c).setTitle('❌ カテゴリーが見つかりません')
        .setDescription(`カテゴリID \`${cfg.kokumin_category_id}\` を確認してください。`)]
    });
    return;
  }

  const channelName = `国民申請-${mcid}`;
  const dup = await findDupTicket(guild, cfg.kokumin_category_id, channelName);

  if (dup) {
    await interaction.editReply({
      embeds: [new EmbedBuilder().setColor(0xf1c40f).setTitle('⚠️ 既に国民申請チケットがあります')
        .setDescription(`重複作成はできません。\n${dup}`)]
    });
    return;
  }

  const ticketCh = await guild.channels.create({
    name: channelName,
    type: ChannelType.GuildText,
    parent: cfg.kokumin_category_id,
    topic: `ticket_type=kokumin | creator_id=${interaction.user.id} | mcid=${mcidRaw}`,
    permissionOverwrites: [
      { id: guild.roles.everyone.id, deny: [PermissionFlagsBits.ViewChannel, PermissionFlagsBits.SendMessages, PermissionFlagsBits.ReadMessageHistory] },
      { id: interaction.user.id,     allow: [PermissionFlagsBits.ViewChannel, PermissionFlagsBits.SendMessages, PermissionFlagsBits.ReadMessageHistory, PermissionFlagsBits.AttachFiles, PermissionFlagsBits.EmbedLinks] }
    ],
    reason: `国民申請チケット: ${interaction.user.tag}`
  });

  await ticketCh.send({
    embeds: [new EmbedBuilder().setColor(0x2ecc71)
      .setDescription('対応者が来るまでお待ちください。\n参加理由(任意)をご記入いただければ幸いです。')
      .setFooter({ text: `作成者: ${interaction.user.tag}` }).setTimestamp()]
  });

  await interaction.editReply({
    embeds: [new EmbedBuilder().setColor(0x2ecc71).setTitle('✅ 国民申請チケットを作成しました')
      .setDescription(`${ticketCh}`)]
  });
}

// ============================================================
// チケット作成: サポート
// ============================================================

async function createSupportTicket(interaction) {
  await interaction.deferReply({ ephemeral: true });

  const cfg = await fetchGuildConfig(interaction.guildId);

  if (!cfg?.support_category_id) {
    await interaction.editReply({
      embeds: [new EmbedBuilder().setColor(0xe74c3c).setTitle('❌ チケット機能無効')
        .setDescription('`/setup-ticket` でサポートカテゴリIDを設定してください。')]
    });
    return;
  }

  const guild   = interaction.guild;
  const reason  = interaction.fields.getTextInputValue(INPUT_SUPPORT_REASON) || '';

  // チャンネル名: サポート-ユーザー名 (sanitize済み)
  const safeUsername  = sanitizeName(interaction.user.username);
  const channelName   = `サポート-${safeUsername || interaction.user.id}`;

  const category = await fetchCategory(guild, cfg.support_category_id);

  if (!category) {
    await interaction.editReply({
      embeds: [new EmbedBuilder().setColor(0xe74c3c).setTitle('❌ カテゴリーが見つかりません')
        .setDescription(`カテゴリID \`${cfg.support_category_id}\` を確認してください。`)]
    });
    return;
  }

  // 同一ユーザーのサポートチケットが既にある場合は重複防止
  const dup = await findDupTicket(guild, cfg.support_category_id, channelName);

  if (dup) {
    await interaction.editReply({
      embeds: [new EmbedBuilder().setColor(0xf1c40f).setTitle('⚠️ 既にサポートチケットがあります')
        .setDescription(`既存のチケットを使用してください。\n${dup}`)]
    });
    return;
  }

  // 権限設定: adminロール + 本人のみ閲覧可
  const overwrites = [
    { id: guild.roles.everyone.id, deny: [PermissionFlagsBits.ViewChannel, PermissionFlagsBits.SendMessages, PermissionFlagsBits.ReadMessageHistory] },
    { id: interaction.user.id,     allow: [PermissionFlagsBits.ViewChannel, PermissionFlagsBits.SendMessages, PermissionFlagsBits.ReadMessageHistory, PermissionFlagsBits.AttachFiles, PermissionFlagsBits.EmbedLinks] }
  ];

  if (cfg.admin_role_id) {
    overwrites.push({
      id: cfg.admin_role_id,
      allow: [PermissionFlagsBits.ViewChannel, PermissionFlagsBits.SendMessages, PermissionFlagsBits.ReadMessageHistory, PermissionFlagsBits.AttachFiles, PermissionFlagsBits.EmbedLinks]
    });
  }

  const ticketCh = await guild.channels.create({
    name: channelName,
    type: ChannelType.GuildText,
    parent: cfg.support_category_id,
    topic: `ticket_type=support | creator_id=${interaction.user.id}`,
    permissionOverwrites: overwrites,
    reason: `サポートチケット: ${interaction.user.tag}`
  });

  const embed = new EmbedBuilder()
    .setColor(0x9b59b6)
    .setTitle('📩 サポートチケット')
    .setDescription('担当者が確認次第ご対応いたします。しばらくお待ちください。')
    .addFields({ name: '作成者', value: `${interaction.user} \`${interaction.user.id}\``, inline: true })
    .setFooter({ text: `作成者: ${interaction.user.tag}` })
    .setTimestamp();

  if (reason) {
    embed.addFields({ name: 'お問い合わせ内容', value: trunc(reason, 800), inline: false });
  }

  await ticketCh.send({ embeds: [embed] });

  await interaction.editReply({
    embeds: [new EmbedBuilder().setColor(0x2ecc71).setTitle('✅ サポートチケットを作成しました')
      .setDescription(`${ticketCh}`)]
  });
}

// ============================================================
// add-gaikou
// ============================================================

async function addUserToGaikouTicket(interaction) {
  await interaction.deferReply({ ephemeral: true });

  const cfg        = await fetchGuildConfig(interaction.guildId);
  const channel    = interaction.channel;
  const targetUser = interaction.options.getUser('user', true);

  const isInGaikouTicket =
    cfg?.gaikou_category_id &&
    channel?.parentId === cfg.gaikou_category_id &&
    channel?.name.endsWith('-外交');

  if (!isInGaikouTicket) {
    await interaction.editReply({
      embeds: [new EmbedBuilder().setColor(0xe74c3c).setTitle('❌ 使用できません')
        .setDescription('このコマンドは外交チケット内でのみ使用できます。')]
    });
    return;
  }

  const creatorId   = getCreatorId(channel);
  const hasGaikouRole = cfg.gaikou_mention_role_id
    ? (interaction.member?.roles?.cache?.has(cfg.gaikou_mention_role_id) ?? false)
    : false;
  const canUse = isAdmin(interaction, cfg) || creatorId === interaction.user.id || hasGaikouRole;

  if (!canUse) {
    await interaction.editReply({
      embeds: [new EmbedBuilder().setColor(0xe74c3c).setTitle('🚫 権限がありません')
        .setDescription('チケット作成者・外交担当ロール・管理者のみ使用できます。')]
    });
    return;
  }

  const member = await interaction.guild.members.fetch(targetUser.id).catch(() => null);

  if (!member) {
    await interaction.editReply({
      embeds: [new EmbedBuilder().setColor(0xe74c3c).setTitle('❌ ユーザーが見つかりません')]
    });
    return;
  }

  await channel.permissionOverwrites.edit(targetUser.id, {
    ViewChannel: true, SendMessages: true, ReadMessageHistory: true,
    AttachFiles: true, EmbedLinks: true
  }, `外交チケットに追加: ${interaction.user.tag}`);

  await channel.send({
    content: `${targetUser} をこの外交チケットに追加しました。`,
    allowedMentions: { users: [targetUser.id] }
  });

  await interaction.editReply({
    embeds: [new EmbedBuilder().setColor(0x2ecc71).setTitle('✅ 追加しました')
      .setDescription(`${targetUser} がこのチャンネルを閲覧できるようになりました。`)]
  });
}

// ============================================================
// 認証処理: DMとログ
// ============================================================

async function sendProviderBlockedDm(userId) {
  const user = await client.users.fetch(userId).catch(() => null);
  if (!user) return 'DM送信失敗: ユーザーを取得できません';

  try {
    await user.send({
      embeds: [new EmbedBuilder().setColor(0xe74c3c).setTitle('認証がブロックされました')
        .setDescription('プロバイダーの問題により認証がブロックされました。\nご自宅に帰宅後、再度認証をお願いいたします。\nそれでも改善されない場合は @sinntika までご連絡ください。')
        .setFooter({ text: '認証BOT' }).setTimestamp()]
    });
    return 'DM送信済み';
  } catch (e) {
    return `DM送信失敗: ${trunc(e.message, 100)}`;
  }
}

async function sendVerificationLog(item, roleResultText, extraText = '') {
  const cfg = await fetchGuildConfig(item.guild_id);
  if (!cfg?.log_channel_id) return;

  const guild = await client.guilds.fetch(item.guild_id).catch(() => null);
  if (!guild) return;

  const channel = await guild.channels.fetch(cfg.log_channel_id).catch(() => null);
  if (!channel?.isTextBased()) return;

  const embed = new EmbedBuilder()
    .setColor(statusColor(item.status))
    .setTitle(item.status === 'approved' ? '✅ 認証成功ログ' : '🚫 認証ブロックログ')
    .setDescription('認証ページでの処理結果です。')
    .addFields(
      { name: 'ユーザー',   value: `<@${item.user_id}>`,         inline: true },
      { name: 'ユーザーID', value: String(item.user_id),          inline: true },
      { name: '接続国',     value: item.ip_country || 'UNKNOWN',  inline: true },
      { name: '認証状態',   value: statusLabel(item.status),      inline: true },
      { name: 'ロール処理', value: roleResultText || '処理なし',  inline: true },
      { name: '認証ID',     value: String(item.id),               inline: true },
      {
        name: 'リスク判定',
        value: [
          `スコア: ${item.risk_score ?? '不明'}`,
          `ISP: ${trunc(item.risk_isp || '不明', 80)}`,
          `組織: ${trunc(item.risk_organization || '不明', 80)}`,
          `ASN: ${item.risk_asn || '不明'}`,
          `理由: ${trunc(item.risk_flags || 'なし', 160)}`
        ].join('\n'),
        inline: false
      }
    )
    .setFooter({ text: '認証BOTログ' }).setTimestamp();

  if (item.status === 'blocked_provider') {
    embed.addFields({ name: 'プロバイダー情報', value: trunc(providerInfo(item), 800), inline: false });
  }

  if (extraText) {
    embed.addFields({ name: '追加処理', value: trunc(extraText, 500), inline: false });
  }

  await channel.send({ embeds: [embed] }).catch(e => console.error('[ログ送信エラー]', e));
}

// ============================================================
// 認証処理: pending ポーリング
// ============================================================

async function processPendingItem(item) {
  let roleResultText = 'ロール処理なし';
  let extraText      = '';

  const cfg   = await fetchGuildConfig(item.guild_id);
  const guild = await client.guilds.fetch(item.guild_id).catch(() => null);

  if (!guild) {
    roleResultText = 'サーバーが見つかりません (BOT未参加)';
    await sendVerificationLog(item, roleResultText);
    await apiPostJson('/mark_done.php', { id: item.id });
    return;
  }

  if (!cfg?.verify_role_id) {
    // /setup 未実施サーバーはスキップ (mark_done だけして詰まらせない)
    roleResultText = 'BOT設定未登録 (/setup を実行してください)';
    await sendVerificationLog(item, roleResultText);
    await apiPostJson('/mark_done.php', { id: item.id });
    return;
  }

  if (item.status === 'approved') {
    const member = await guild.members.fetch(item.user_id).catch(() => null);

    if (!member) {
      roleResultText = 'メンバーが見つかりません';
    } else {
      try {
        await member.roles.add(cfg.verify_role_id, '認証成功');
        roleResultText = '認証ロールを付与しました';
      } catch (e) {
        roleResultText = `ロール付与失敗: ${trunc(e.message, 200)}`;
        console.error('[ロール付与エラー]', e);
      }
    }
  } else {
    roleResultText = 'ブロックされたためロール未付与';

    if (item.status === 'blocked_provider') {
      extraText = await sendProviderBlockedDm(item.user_id);
    }
  }

  await sendVerificationLog(item, roleResultText, extraText);
  await apiPostJson('/mark_done.php', { id: item.id });
}

let isPolling = false;

async function pollPending() {
  if (isPolling) return;
  isPolling = true;

  try {
    const data = await apiGetJson('/pending.php');

    for (const item of data.items || []) {
      try {
        await processPendingItem(item);
      } catch (e) {
        console.error('[認証処理エラー]', e);
      }
    }
  } catch (e) {
    console.error('[API確認エラー]', e.message);
  } finally {
    isPolling = false;
  }
}

// ============================================================
// Ready
// ============================================================

client.once(Events.ClientReady, () => {
  console.log(`✅ ログイン: ${client.user.tag}`);
  console.log(`🔁 認証確認間隔: ${POLL_INTERVAL_MS}ms`);

  pollPending().catch(e => console.error('[初回ポーリングエラー]', e));
  setInterval(() => pollPending().catch(e => console.error('[定期ポーリングエラー]', e)), POLL_INTERVAL_MS);
});

// ============================================================
// InteractionCreate
// ============================================================

client.on(Events.InteractionCreate, async interaction => {
  try {
    if (!interaction.inGuild()) return;

    // ---- ボタン ----
    if (interaction.isButton()) {
      if (interaction.customId === BTN_VERIFY) {
        const url   = createVerifyUrl(interaction.guildId, interaction.user);
        const embed = embedPrivateVerify(interaction.guild?.name);
        await interaction.reply({
          embeds: [embed],
          components: [new ActionRowBuilder().addComponents(
            new ButtonBuilder().setLabel('認証ページを開く').setStyle(ButtonStyle.Link).setURL(url)
          )],
          ephemeral: true
        });
        return;
      }

      if (interaction.customId === BTN_GAIKOU_PANEL)  { await showGaikouModal(interaction);  return; }
      if (interaction.customId === BTN_KOKUMIN_PANEL)  { await showKokuminModal(interaction); return; }
      if (interaction.customId === BTN_SUPPORT_PANEL)  { await showSupportModal(interaction); return; }
      return;
    }

    // ---- モーダル ----
    if (interaction.isModalSubmit()) {
      if (interaction.customId === MODAL_GAIKOU)  { await createGaikouTicket(interaction);  return; }
      if (interaction.customId === MODAL_KOKUMIN) { await createKokuminTicket(interaction); return; }
      if (interaction.customId === MODAL_SUPPORT) { await createSupportTicket(interaction); return; }
      return;
    }

    if (!interaction.isChatInputCommand()) return;

    const cmd = interaction.commandName;

    // ---- add-gaikou は権限チェック内部で行う ----
    if (cmd === 'add-gaikou') {
      await addUserToGaikouTicket(interaction);
      return;
    }

    // ---- 設定コマンド (管理者権限チェック) ----
    // /setup /setup-ticket /setup-show は Administratorのみ許可
    // (コマンド側でも setDefaultMemberPermissions 済みだが念のため)
    if (['setup', 'setup-ticket', 'setup-show'].includes(cmd)) {
      if (!(interaction.memberPermissions?.has(PermissionFlagsBits.Administrator) ?? false)) {
        await interaction.reply({
          embeds: [new EmbedBuilder().setColor(0xe74c3c).setTitle('🚫 権限がありません')
            .setDescription('このコマンドはサーバー管理者のみ使用できます。')],
          ephemeral: true
        });
        return;
      }

      if (cmd === 'setup')       { await handleSetup(interaction);      return; }
      if (cmd === 'setup-ticket') { await handleSetupTicket(interaction); return; }
      if (cmd === 'setup-show')   { await handleSetupShow(interaction);   return; }
    }

    // ---- 以降は admin_role_id も含めたチェック ----
    const cfg = await fetchGuildConfig(interaction.guildId);

    if (!isAdmin(interaction, cfg)) {
      await interaction.reply({
        embeds: [new EmbedBuilder().setColor(0xe74c3c).setTitle('🚫 権限がありません')
          .setDescription('このコマンドは管理者限定です。')],
        ephemeral: true
      });
      return;
    }

    await interaction.deferReply({ ephemeral: true });

    if (cmd === 'ping') {
      await interaction.editReply({
        embeds: [new EmbedBuilder().setColor(0x2ecc71).setTitle('🏓 接続確認')
          .setDescription('BOTは正常に起動しています。')
          .addFields(
            { name: 'BOT状態',     value: '✅ オンライン',          inline: true },
            { name: '通信速度',     value: `${client.ws.ping}ms`,   inline: true },
            { name: '認証API',      value: process.env.API_BASE_URL, inline: false },
            { name: '認証確認間隔', value: `${POLL_INTERVAL_MS}ms`, inline: true }
          )
          .setFooter({ text: '認証BOT' }).setTimestamp()]
      });
      return;
    }

    if (cmd === 'verifypanel') {
      if (!interaction.channel?.isTextBased()) {
        await interaction.editReply({
          embeds: [new EmbedBuilder().setColor(0xe74c3c).setTitle('❌ エラー')
            .setDescription('このチャンネルには認証パネルを送信できません。')]
        });
        return;
      }
      await interaction.channel.send({
        embeds: [embedVerifyPanel()],
        components: [new ActionRowBuilder().addComponents(
          new ButtonBuilder().setCustomId(BTN_VERIFY).setLabel('認証する').setStyle(ButtonStyle.Success)
        )]
      });
      await interaction.editReply({
        embeds: [new EmbedBuilder().setColor(0x2ecc71).setTitle('✅ 認証パネルを設置しました')]
      });
      return;
    }

    if (cmd === 'create-gaikou')  { await handleCreateGaikou(interaction, cfg);  return; }
    if (cmd === 'create-kokumin') { await handleCreateKokumin(interaction, cfg);  return; }
    if (cmd === 'ticket-support') { await handleCreateSupport(interaction, cfg);  return; }

    if (cmd === 'search') {
      const user = interaction.options.getUser('user', true);
      let data;

      try {
        data = await apiGetJson('/search.php', { guild_id: interaction.guildId, user_id: user.id });
      } catch (e) {
        await interaction.editReply({
          embeds: [new EmbedBuilder().setColor(0xe74c3c).setTitle('❌ 検索失敗')
            .setDescription(trunc(apiErrorJa(e.message), 3000))
            .setFooter({ text: '認証BOT' }).setTimestamp()]
        });
        return;
      }

      if (!data.item) {
        await interaction.editReply({
          embeds: [new EmbedBuilder().setColor(0xf1c40f).setTitle('🔍 認証情報検索')
            .setDescription('このサーバーでの認証データは見つかりませんでした。')
            .addFields(
              { name: '対象ユーザー', value: `${user} \`${user.id}\``, inline: false },
              { name: '認証状態',     value: 'データなし',              inline: true }
            )
            .setFooter({ text: 'まだ認証していない可能性があります' }).setTimestamp()]
        });
        return;
      }

      const item  = data.item;
      const embed = new EmbedBuilder()
        .setColor(statusColor(item.status)).setTitle('🔍 認証情報検索')
        .setDescription('このサーバーでの最新認証データです。')
        .addFields(
          { name: '対象ユーザー', value: `${user} \`${user.id}\``,     inline: false },
          { name: '接続国',       value: item.ip_country || 'UNKNOWN', inline: true },
          { name: '認証状態',     value: statusLabel(item.status),     inline: true },
          { name: '重複IP判定',   value: Number(item.is_duplicate_ip) === 1 ? 'あり' : 'なし', inline: true },
          { name: '認証日時',     value: item.created_at || '不明',    inline: false },
          { name: 'BOT処理済み',  value: Number(item.processed) === 1 ? 'はい' : 'いいえ', inline: true },
          { name: '履歴件数',     value: String(data.total_records ?? '不明'), inline: true }
        )
        .setFooter({ text: '認証BOT' }).setTimestamp();

      if (item.status === 'blocked_provider') {
        embed.addFields({ name: 'プロバイダー情報', value: trunc(providerInfo(item), 800), inline: false });
      }

      await interaction.editReply({ embeds: [embed] });
      return;
    }

    if (cmd === 'ipclear') {
      const user = interaction.options.getUser('user', true);
      let data;

      try {
        data = await apiPostJson('/ipclear.php', { guild_id: interaction.guildId, user_id: user.id });
      } catch (e) {
        await interaction.editReply({
          embeds: [new EmbedBuilder().setColor(0xe74c3c).setTitle('❌ IP履歴削除失敗')
            .setDescription(trunc(apiErrorJa(e.message), 3000))
            .setFooter({ text: '認証BOT' }).setTimestamp()]
        });
        return;
      }

      await interaction.editReply({
        embeds: [new EmbedBuilder().setColor(0xe67e22).setTitle('🧹 IP認証履歴を削除しました')
          .addFields(
            { name: '対象ユーザー', value: `${user} \`${user.id}\``, inline: false },
            { name: '削除件数',     value: String(data.deleted ?? 0), inline: true }
          )
          .setFooter({ text: 'このユーザーは再認証できるようになります' }).setTimestamp()]
      });
      return;
    }

    await interaction.editReply({
      embeds: [new EmbedBuilder().setColor(0x95a5a6).setTitle('❔ 不明なコマンド')]
    });

  } catch (error) {
    console.error('[コマンド処理エラー]', error);

    const embed = new EmbedBuilder().setColor(0xe74c3c).setTitle('❌ エラーが発生しました')
      .setDescription(trunc(apiErrorJa(error.message || '不明なエラー'), 3000))
      .setFooter({ text: '認証BOT' }).setTimestamp();

    if (interaction.isRepliable()) {
      if (interaction.deferred) {
        await interaction.editReply({ embeds: [embed] }).catch(() => {});
      } else if (interaction.replied) {
        await interaction.followUp({ embeds: [embed], ephemeral: true }).catch(() => {});
      } else {
        await interaction.reply({ embeds: [embed], ephemeral: true }).catch(() => {});
      }
    }
  }
});

client.login(process.env.DISCORD_TOKEN);
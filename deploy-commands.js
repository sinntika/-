require('dotenv').config();

const {
  REST,
  Routes,
  SlashCommandBuilder,
  PermissionFlagsBits
} = require('discord.js');

// ============================================================
// 環境変数チェック
// ============================================================

const requiredEnv = ['DISCORD_TOKEN', 'DISCORD_CLIENT_ID'];

for (const key of requiredEnv) {
  if (!process.env[key] || process.env[key].trim() === '') {
    console.error(`❌ 必須環境変数が未設定です: ${key}`);
    process.exit(1);
  }
}

// ============================================================
// スラッシュコマンド定義
// ============================================================

const commands = [
  // ---- 疎通確認 ----
  new SlashCommandBuilder()
    .setName('ping')
    .setDescription('BOTの疎通確認をします')
    .setDefaultMemberPermissions(PermissionFlagsBits.Administrator)
    .setDMPermission(false),

  // ---- 認証設定 ----
  new SlashCommandBuilder()
    .setName('setup')
    .setDescription('認証BOTの基本設定をします (認証ロール・ログチャンネル)')
    .addRoleOption(opt =>
      opt.setName('verify_role')
        .setDescription('認証成功時に付与するロール')
        .setRequired(true)
    )
    .addChannelOption(opt =>
      opt.setName('log_channel')
        .setDescription('認証ログを送信するチャンネル')
        .setRequired(true)
    )
    .addRoleOption(opt =>
      opt.setName('admin_role')
        .setDescription('管理コマンドを使えるロール (未指定 = Administratorのみ)')
        .setRequired(false)
    )
    .setDefaultMemberPermissions(PermissionFlagsBits.Administrator)
    .setDMPermission(false),

  // ---- チケット設定 ----
  new SlashCommandBuilder()
    .setName('setup-ticket')
    .setDescription('チケット機能の設定をします (カテゴリID等)')
    .addStringOption(opt =>
      opt.setName('gaikou_category_id')
        .setDescription('外交チケット用カテゴリのチャンネルID (無効化は "none")')
        .setRequired(false)
    )
    .addRoleOption(opt =>
      opt.setName('gaikou_mention_role')
        .setDescription('外交チケット作成時にメンションするロール')
        .setRequired(false)
    )
    .addStringOption(opt =>
      opt.setName('kokumin_category_id')
        .setDescription('国民申請チケット用カテゴリのチャンネルID (無効化は "none")')
        .setRequired(false)
    )
    .addStringOption(opt =>
      opt.setName('support_category_id')
        .setDescription('サポートチケット用カテゴリのチャンネルID (無効化は "none")')
        .setRequired(false)
    )
    .setDefaultMemberPermissions(PermissionFlagsBits.Administrator)
    .setDMPermission(false),

  // ---- 設定確認 ----
  new SlashCommandBuilder()
    .setName('setup-show')
    .setDescription('現在のBOT設定を表示します')
    .setDefaultMemberPermissions(PermissionFlagsBits.Administrator)
    .setDMPermission(false),

  // ---- 認証パネル ----
  new SlashCommandBuilder()
    .setName('verifypanel')
    .setDescription('認証パネルをこのチャンネルに設置します')
    .setDefaultMemberPermissions(PermissionFlagsBits.Administrator)
    .setDMPermission(false),

  // ---- 認証情報検索 ----
  new SlashCommandBuilder()
    .setName('search')
    .setDescription('指定ユーザーの認証情報を検索します')
    .addUserOption(opt =>
      opt.setName('user').setDescription('検索するDiscordユーザー').setRequired(true)
    )
    .setDefaultMemberPermissions(PermissionFlagsBits.Administrator)
    .setDMPermission(false),

  // ---- IP履歴削除 ----
  new SlashCommandBuilder()
    .setName('ipclear')
    .setDescription('指定ユーザーのIP認証履歴をリセットします')
    .addUserOption(opt =>
      opt.setName('user').setDescription('IP履歴をリセットするDiscordユーザー').setRequired(true)
    )
    .setDefaultMemberPermissions(PermissionFlagsBits.Administrator)
    .setDMPermission(false),

  // ---- チケットパネル設置 ----
  new SlashCommandBuilder()
    .setName('create-gaikou')
    .setDescription('外交申請用チケットパネルをこのチャンネルに設置します')
    .setDefaultMemberPermissions(PermissionFlagsBits.Administrator)
    .setDMPermission(false),

  new SlashCommandBuilder()
    .setName('create-kokumin')
    .setDescription('国民申請用チケットパネルをこのチャンネルに設置します')
    .setDefaultMemberPermissions(PermissionFlagsBits.Administrator)
    .setDMPermission(false),

  new SlashCommandBuilder()
    .setName('ticket-support')
    .setDescription('サポートチケットパネルをこのチャンネルに設置します')
    .setDefaultMemberPermissions(PermissionFlagsBits.Administrator)
    .setDMPermission(false),

  // ---- 外交チケットへユーザー追加 ----
  new SlashCommandBuilder()
    .setName('add-gaikou')
    .setDescription('外交チケットにDiscordユーザーを追加します')
    .addUserOption(opt =>
      opt.setName('user').setDescription('追加するDiscordユーザー').setRequired(true)
    )
    .setDMPermission(false)
].map(cmd => cmd.toJSON());

// ============================================================
// グローバルコマンドとしてデプロイ
// (全サーバーに反映。反映まで最大1時間かかる場合あり)
// 特定サーバーのみにしたい場合は Routes.applicationGuildCommands に変更
// ============================================================

async function main() {
  const rest = new REST({ version: '10' }).setToken(process.env.DISCORD_TOKEN);

  console.log('🔄 グローバルスラッシュコマンドをデプロイ中...');

  await rest.put(
    Routes.applicationCommands(process.env.DISCORD_CLIENT_ID),
    { body: commands }
  );

  console.log(`✅ ${commands.length} コマンドをグローバルデプロイしました。`);
  console.log('⏳ 全サーバーへの反映には最大1時間かかることがあります。');
}

main().catch(err => {
  console.error('❌ デプロイ失敗:', err);
  process.exit(1);
});
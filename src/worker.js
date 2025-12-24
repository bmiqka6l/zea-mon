const SESSION_DURATION_MS = 10 * 24 * 60 * 60 * 1000;

function jsonResponse(data, status = 200, extraHeaders = {}) {
  const headers = {
    'Content-Type': 'application/json; charset=utf-8',
    ...corsHeaders(),
    ...extraHeaders
  };
  return new Response(JSON.stringify(data), { status, headers });
}

function corsHeaders() {
  return {
    'Access-Control-Allow-Origin': '*',
    'Access-Control-Allow-Methods': 'GET,POST,DELETE,OPTIONS',
    'Access-Control-Allow-Headers': 'Content-Type, x-admin-password, x-session-token'
  };
}

function emptyOk() {
  return new Response(null, { status: 204, headers: corsHeaders() });
}

function hexToBytes(hex) {
  if (!hex || hex.length % 2 !== 0) {
    throw new Error('Invalid hex string');
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < bytes.length; i += 1) {
    bytes[i] = parseInt(hex.substr(i * 2, 2), 16);
  }
  return bytes;
}

function bytesToHex(bytes) {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

function randomToken() {
  const bytes = new Uint8Array(24);
  crypto.getRandomValues(bytes);
  const base64 = btoa(String.fromCharCode(...bytes))
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
  return `session_${base64}`;
}

async function encryptToken(token, secretHex) {
  if (!secretHex || secretHex.length !== 64) {
    throw new Error('密钥必须是64位十六进制字符串');
  }
  const key = await crypto.subtle.importKey(
    'raw',
    hexToBytes(secretHex),
    'AES-GCM',
    false,
    ['encrypt']
  );
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const data = new TextEncoder().encode(token);
  const encrypted = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, data);
  return {
    encrypted: bytesToHex(new Uint8Array(encrypted)),
    iv: bytesToHex(iv)
  };
}

async function decryptToken(payload, secretHex) {
  if (!secretHex || secretHex.length !== 64) {
    throw new Error('密钥必须是64位十六进制字符串');
  }
  const key = await crypto.subtle.importKey(
    'raw',
    hexToBytes(secretHex),
    'AES-GCM',
    false,
    ['decrypt']
  );
  const iv = hexToBytes(payload.iv);
  const encryptedBytes = hexToBytes(payload.encrypted);
  const decrypted = await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, encryptedBytes);
  return new TextDecoder().decode(decrypted);
}

async function readJson(request) {
  try {
    return await request.json();
  } catch (error) {
    return null;
  }
}

async function loadAdminPassword(env) {
  const result = await env.DB.prepare('SELECT password FROM admin_password WHERE id = 1').first();
  return result ? result.password : null;
}

async function saveAdminPassword(env, password) {
  await env.DB.prepare('INSERT INTO admin_password (id, password) VALUES (1, ?)').bind(password).run();
}

async function cleanupExpiredSessions(env) {
  const cutoff = Date.now() - SESSION_DURATION_MS;
  await env.DB.prepare('DELETE FROM sessions WHERE created_at < ?').bind(cutoff).run();
}

async function getSession(env, token) {
  const result = await env.DB.prepare('SELECT token, created_at FROM sessions WHERE token = ?').bind(token).first();
  return result || null;
}

async function deleteSession(env, token) {
  await env.DB.prepare('DELETE FROM sessions WHERE token = ?').bind(token).run();
}

async function requireAuth(request, env) {
  const password = request.headers.get('x-admin-password');
  const sessionToken = request.headers.get('x-session-token');
  const savedPassword = await loadAdminPassword(env);

  if (!savedPassword) {
    return { ok: true };
  }

  if (sessionToken) {
    const session = await getSession(env, sessionToken);
    if (session) {
      if (Date.now() - session.created_at < SESSION_DURATION_MS) {
        return { ok: true };
      }
      await deleteSession(env, sessionToken);
      return { ok: false, response: jsonResponse({ error: 'Session已过期，请重新登录' }, 401) };
    }
  }

  if (password && password === savedPassword) {
    return { ok: true };
  }

  return { ok: false, response: jsonResponse({ error: '密码错误或Session无效' }, 401) };
}

function parseEnvAccounts(env) {
  if (!env.ACCOUNTS) {
    return [];
  }

  try {
    return env.ACCOUNTS.split(',')
      .map((item) => item.split(':'))
      .map(([name, token]) => ({ name: name?.trim(), token: token?.trim() }))
      .filter((acc) => acc.name && acc.token);
  } catch (error) {
    console.error('解析环境变量 ACCOUNTS 失败:', error.message);
    return [];
  }
}

async function loadServerAccounts(env, encryptionEnabled) {
  const rows = await env.DB.prepare(
    'SELECT id, name, token_encrypted, token_iv, token_plain, sort_index FROM accounts ORDER BY sort_index ASC'
  ).all();
  const accounts = rows.results || [];

  if (!encryptionEnabled) {
    return accounts.map((row) => ({
      id: row.id,
      name: row.name,
      token: row.token_plain || row.token_encrypted || null
    }));
  }

  const decrypted = [];
  for (const row of accounts) {
    if (row.token_encrypted && row.token_iv) {
      try {
        const token = await decryptToken({ encrypted: row.token_encrypted, iv: row.token_iv }, env.ACCOUNTS_SECRET);
        decrypted.push({ id: row.id, name: row.name, token });
      } catch (error) {
        console.error(`解密账号 [${row.name}] 的 Token 失败:`, error.message);
        decrypted.push({ id: row.id, name: row.name, token: null });
      }
    } else {
      decrypted.push({ id: row.id, name: row.name, token: row.token_plain || null });
    }
  }
  return decrypted;
}

async function deleteAccountById(env, accountId) {
  const id = Number(accountId);
  if (!Number.isFinite(id) || id <= 0) {
    return false;
  }
  const result = await env.DB.prepare('DELETE FROM accounts WHERE id = ?').bind(id).run();
  return result?.meta?.changes > 0;
}

async function nextSortIndex(env) {
  const result = await env.DB.prepare('SELECT COALESCE(MAX(sort_index), -1) + 1 AS next_index FROM accounts').first();
  return result?.next_index ?? 0;
}

async function buildTokenFields(env, accountToken, encryptionEnabled, fallback) {
  if (accountToken) {
    if (encryptionEnabled) {
      try {
        const encrypted = await encryptToken(accountToken, env.ACCOUNTS_SECRET);
        return { tokenEncrypted: encrypted.encrypted, tokenIv: encrypted.iv, tokenPlain: null };
      } catch (error) {
        console.error(`加密账号 Token 失败:`, error.message);
      }
    }
    return { tokenEncrypted: null, tokenIv: null, tokenPlain: accountToken };
  }

  return {
    tokenEncrypted: fallback?.token_encrypted || null,
    tokenIv: fallback?.token_iv || null,
    tokenPlain: fallback?.token_plain || null
  };
}

async function insertAccount(env, account, encryptionEnabled) {
  const sortIndex = await nextSortIndex(env);
  const tokenFields = await buildTokenFields(env, account.token, encryptionEnabled, null);

  try {
    await env.DB.prepare(
      'INSERT INTO accounts (name, token_encrypted, token_iv, token_plain, sort_index) VALUES (?, ?, ?, ?, ?)'
    ).bind(account.name, tokenFields.tokenEncrypted, tokenFields.tokenIv, tokenFields.tokenPlain, sortIndex).run();
  } catch (error) {
    // If name exists, update token instead of failing
    const existing = await env.DB.prepare('SELECT id FROM accounts WHERE name = ?').bind(account.name).first();
    if (!existing) {
      throw error;
    }
    await env.DB.prepare(
      'UPDATE accounts SET token_encrypted = ?, token_iv = ?, token_plain = ?, sort_index = ? WHERE id = ?'
    ).bind(tokenFields.tokenEncrypted, tokenFields.tokenIv, tokenFields.tokenPlain, sortIndex, existing.id).run();
    return { id: existing.id, name: account.name };
  }

  const inserted = await env.DB.prepare('SELECT id FROM accounts WHERE name = ?').bind(account.name).first();
  return { id: inserted?.id, name: account.name };
}

async function postZeabur(token, body) {
  const response = await fetch('https://api.zeabur.com/graphql', {
    method: 'POST',
    headers: {
      'Authorization': `Bearer ${token}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(body)
  });

  const text = await response.text();
  try {
    return JSON.parse(text);
  } catch (error) {
    throw new Error('Invalid JSON response');
  }
}

async function fetchAccountData(token) {
  const userQuery = `
    query {
      me {
        _id
        username
        email
        credit
      }
    }
  `;

  const projectsQuery = `
    query {
      projects {
        edges {
          node {
            _id
            name
            region {
              name
            }
            environments {
              _id
            }
            services {
              _id
              name
              status
              template
              resourceLimit {
                cpu
                memory
              }
              domains {
                domain
                isGenerated
              }
            }
          }
        }
      }
    }
  `;

  const aihubQuery = `
    query GetAIHubTenant {
      aihubTenant {
        balance
        keys {
          keyID
          alias
          cost
        }
      }
    }
  `;

  const [userData, projectsData, aihubData] = await Promise.all([
    postZeabur(token, { query: userQuery }),
    postZeabur(token, { query: projectsQuery }),
    postZeabur(token, { query: aihubQuery }).catch(() => ({ data: { aihubTenant: null } }))
  ]);

  return {
    user: userData.data?.me || {},
    projects: (projectsData.data?.projects?.edges || []).map((edge) => edge.node),
    aihub: aihubData.data?.aihubTenant || null
  };
}

async function fetchUsageData(token, userId) {
  const now = new Date();
  const year = now.getFullYear();
  const month = now.getMonth() + 1;
  const fromDate = `${year}-${String(month).padStart(2, '0')}-01`;
  const tomorrow = new Date(now);
  tomorrow.setDate(tomorrow.getDate() + 1);
  const toDate = `${tomorrow.getFullYear()}-${String(tomorrow.getMonth() + 1).padStart(2, '0')}-${String(tomorrow.getDate()).padStart(2, '0')}`;

  const usageQuery = {
    operationName: 'GetHeaderMonthlyUsage',
    variables: {
      from: fromDate,
      to: toDate,
      groupByEntity: 'PROJECT',
      groupByTime: 'DAY',
      groupByType: 'ALL',
      userID: userId
    },
    query: `query GetHeaderMonthlyUsage($from: String!, $to: String!, $groupByEntity: GroupByEntity, $groupByTime: GroupByTime, $groupByType: GroupByType, $userID: ObjectID!) {
      usages(
        from: $from
        to: $to
        groupByEntity: $groupByEntity
        groupByTime: $groupByTime
        groupByType: $groupByType
        userID: $userID
      ) {
        categories
        data {
          id
          name
          groupByEntity
          usageOfEntity
          __typename
        }
        __typename
      }
    }`
  };

  const result = await postZeabur(token, usageQuery);
  const usages = result.data?.usages?.data || [];

  const projectCosts = {};
  let totalUsage = 0;

  usages.forEach((project) => {
    const projectTotal = project.usageOfEntity.reduce((a, b) => a + b, 0);
    const displayCost = projectTotal > 0 ? Math.ceil(projectTotal * 100) / 100 : 0;
    projectCosts[project.id] = displayCost;
    totalUsage += projectTotal;
  });

  return {
    projectCosts,
    totalUsage,
    freeQuotaRemaining: 5 - totalUsage,
    freeQuotaLimit: 5
  };
}

function pickAccountToken(accounts, accountId) {
  return accounts.find((acc) => (acc.id?.toString() || acc.name) === accountId || acc.name === accountId);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (!url.pathname.startsWith('/api/')) {
      if (env.ASSETS) {
        return env.ASSETS.fetch(request);
      }
      return new Response('Not Found', { status: 404 });
    }

    if (request.method === 'OPTIONS') {
      return emptyOk();
    }

    const encryptionEnabled = !!(env.ACCOUNTS_SECRET && env.ACCOUNTS_SECRET.length === 64);

    try {
      await cleanupExpiredSessions(env);

      if (url.pathname === '/api/check-encryption' && request.method === 'GET') {
        const bytes = new Uint8Array(32);
        crypto.getRandomValues(bytes);
        const suggestedSecret = bytesToHex(bytes);
        return jsonResponse({ isConfigured: encryptionEnabled, suggestedSecret });
      }

      if (url.pathname === '/api/check-password' && request.method === 'GET') {
        const savedPassword = await loadAdminPassword(env);
        return jsonResponse({ hasPassword: !!savedPassword });
      }

      if (url.pathname === '/api/set-password' && request.method === 'POST') {
        const payload = await readJson(request);
        const password = payload?.password;
        const savedPassword = await loadAdminPassword(env);

        if (savedPassword) {
          return jsonResponse({ error: '密码已设置，无法重复设置' }, 400);
        }

        if (!password || password.length < 6) {
          return jsonResponse({ error: '密码长度至少6位' }, 400);
        }

        await saveAdminPassword(env, password);
        console.log('管理员密码已设置');
        return jsonResponse({ success: true });
      }

      if (url.pathname === '/api/verify-password' && request.method === 'POST') {
        const payload = await readJson(request);
        const password = payload?.password;
        const savedPassword = await loadAdminPassword(env);

        if (!savedPassword) {
          return jsonResponse({ success: false, error: '请先设置密码' }, 400);
        }

        if (password === savedPassword) {
          const sessionToken = randomToken();
          await env.DB.prepare('INSERT INTO sessions (token, created_at) VALUES (?, ?)').bind(sessionToken, Date.now()).run();
          console.log(`用户登录成功，生成Session: ${sessionToken.substring(0, 20)}...`);
          return jsonResponse({ success: true, sessionToken });
        }

        return jsonResponse({ success: false, error: '密码错误' }, 401);
      }

      if (url.pathname === '/api/version' && request.method === 'GET') {
        return jsonResponse({ version: env.WORKER_VERSION || '1.0.2' });
      }

      if (url.pathname === '/api/latest-version' && request.method === 'GET') {
        try {
          const response = await fetch('https://raw.githubusercontent.com/jiujiu532/zeabur-monitor/main/package.json', { method: 'GET' });
          const data = await response.json();
          return jsonResponse({ version: data.version });
        } catch (error) {
          return jsonResponse({ error: `获取最新版本失败: ${error.message}` }, 500);
        }
      }

      if (url.pathname === '/api/accounts' && request.method === 'GET') {
        return jsonResponse([]);
      }

      if (url.pathname === '/api/projects' && request.method === 'GET') {
        return jsonResponse([]);
      }

      const auth = await requireAuth(request, env);
      if (!auth.ok) {
        return auth.response;
      }

      if (url.pathname === '/api/server-accounts' && request.method === 'GET') {
        const serverAccounts = await loadServerAccounts(env, encryptionEnabled);
        const envAccounts = parseEnvAccounts(env);
        const allAccounts = [...envAccounts, ...serverAccounts];
        return jsonResponse(allAccounts);
      }

      if (url.pathname === '/api/server-accounts' && request.method === 'POST') {
        const payload = await readJson(request);
        const accounts = payload?.accounts;
        const singleAccount = payload?.account || payload;

        if (accounts && Array.isArray(accounts)) {
          return jsonResponse({ error: '不支持批量保存账号，请使用单条新增或更新接口' }, 400);
        }

        if (!singleAccount || !singleAccount.name || !singleAccount.token) {
          return jsonResponse({ error: '账号名称和 API Token 不能为空' }, 400);
        }

        const saved = await insertAccount(env, singleAccount, encryptionEnabled);
        return jsonResponse({ success: true, account: saved });
      }

      if (url.pathname.startsWith('/api/server-accounts/') && request.method === 'DELETE') {
        const accountId = url.pathname.split('/').pop();
        const removed = await deleteAccountById(env, accountId);
        if (!removed) {
          return jsonResponse({ error: '账号不存在' }, 404);
        }

        return jsonResponse({ success: true, message: '账号已删除' });
      }

      if (url.pathname === '/api/validate-account' && request.method === 'POST') {
        const payload = await readJson(request);
        const accountName = payload?.accountName;
        const apiToken = payload?.apiToken;

        if (!accountName || !apiToken) {
          return jsonResponse({ error: '账号名称和 API Token 不能为空' }, 400);
        }

        try {
          const { user } = await fetchAccountData(apiToken);
          if (user?._id) {
            return jsonResponse({
              success: true,
              message: '账号验证成功！',
              userData: user,
              accountName,
              apiToken
            });
          }
          return jsonResponse({ error: 'API Token 无效或没有权限' }, 400);
        } catch (error) {
          return jsonResponse({ error: `API Token 验证失败: ${error.message}` }, 400);
        }
      }

      if (url.pathname === '/api/temp-accounts' && request.method === 'POST') {
        const payload = await readJson(request);
        const accounts = payload?.accounts;

        if (!accounts || !Array.isArray(accounts)) {
          return jsonResponse({ error: '无效的账号列表' }, 400);
        }

        const results = await Promise.all(accounts.map(async (account) => {
          try {
            const { user, projects, aihub } = await fetchAccountData(account.token);
            let usageData = { totalUsage: 0, freeQuotaRemaining: 5, freeQuotaLimit: 5 };
            if (user._id) {
              try {
                usageData = await fetchUsageData(account.token, user._id, projects);
              } catch (error) {
                console.log(`获取用量失败: ${error.message}`);
              }
            }

            const creditInCents = Math.round(usageData.freeQuotaRemaining * 100);

            return {
              name: account.name,
              success: true,
              data: {
                ...user,
                credit: creditInCents,
                totalUsage: usageData.totalUsage,
                freeQuotaLimit: usageData.freeQuotaLimit
              },
              aihub
            };
          } catch (error) {
            return { name: account.name, success: false, error: error.message };
          }
        }));

        return jsonResponse(results);
      }

      if (url.pathname === '/api/temp-projects' && request.method === 'POST') {
        const payload = await readJson(request);
        const accounts = payload?.accounts;

        if (!accounts || !Array.isArray(accounts)) {
          return jsonResponse({ error: '无效的账号列表' }, 400);
        }

        const results = await Promise.all(accounts.map(async (account) => {
          try {
            const { user, projects } = await fetchAccountData(account.token);
            let projectCosts = {};
            if (user._id) {
              try {
                const usageData = await fetchUsageData(account.token, user._id, projects);
                projectCosts = usageData.projectCosts;
              } catch (error) {
                console.log(`获取用量失败: ${error.message}`);
              }
            }

            const projectsWithCost = projects.map((project) => {
              const cost = projectCosts[project._id] || 0;
              return {
                _id: project._id,
                name: project.name,
                region: project.region?.name || 'Unknown',
                environments: project.environments || [],
                services: project.services || [],
                cost,
                hasCostData: cost > 0
              };
            });

            return { name: account.name, success: true, projects: projectsWithCost };
          } catch (error) {
            return { name: account.name, success: false, error: error.message };
          }
        }));

        return jsonResponse(results);
      }

      if (url.pathname === '/api/service/pause' && request.method === 'POST') {
        const payload = await readJson(request);
        const { token, serviceId, environmentId } = payload || {};

        if (!token || !serviceId || !environmentId) {
          return jsonResponse({ error: '缺少必要参数' }, 400);
        }

        try {
          const mutation = `mutation { suspendService(serviceID: "${serviceId}", environmentID: "${environmentId}") }`;
          const result = await postZeabur(token, { query: mutation });
          if (result.data?.suspendService) {
            return jsonResponse({ success: true, message: '服务已暂停' });
          }
          return jsonResponse({ error: '暂停失败', details: result }, 400);
        } catch (error) {
          return jsonResponse({ error: `暂停服务失败: ${error.message}` }, 500);
        }
      }

      if (url.pathname === '/api/service/restart' && request.method === 'POST') {
        const payload = await readJson(request);
        const { token, serviceId, environmentId } = payload || {};

        if (!token || !serviceId || !environmentId) {
          return jsonResponse({ error: '缺少必要参数' }, 400);
        }

        try {
          const mutation = `mutation { restartService(serviceID: "${serviceId}", environmentID: "${environmentId}") }`;
          const result = await postZeabur(token, { query: mutation });
          if (result.data?.restartService) {
            return jsonResponse({ success: true, message: '服务已重启' });
          }
          return jsonResponse({ error: '重启失败', details: result }, 400);
        } catch (error) {
          return jsonResponse({ error: `重启服务失败: ${error.message}` }, 500);
        }
      }

      if (url.pathname === '/api/service/logs' && request.method === 'POST') {
        const payload = await readJson(request);
        const { token, serviceId, environmentId, projectId, limit = 200 } = payload || {};

        if (!token || !serviceId || !environmentId || !projectId) {
          return jsonResponse({ error: '缺少必要参数' }, 400);
        }

        try {
          const query = `
            query {
              runtimeLogs(
                projectID: "${projectId}"
                serviceID: "${serviceId}"
                environmentID: "${environmentId}"
              ) {
                message
                timestamp
              }
            }
          `;
          const result = await postZeabur(token, { query });
          if (result.data?.runtimeLogs) {
            const sortedLogs = result.data.runtimeLogs.sort((a, b) => new Date(a.timestamp) - new Date(b.timestamp));
            const logs = sortedLogs.slice(-limit);
            return jsonResponse({
              success: true,
              logs,
              count: logs.length,
              totalCount: result.data.runtimeLogs.length
            });
          }
          return jsonResponse({ error: '获取日志失败', details: result }, 400);
        } catch (error) {
          return jsonResponse({ error: `获取日志失败: ${error.message}` }, 500);
        }
      }

      if (url.pathname === '/api/project/rename' && request.method === 'POST') {
        const payload = await readJson(request);
        const { accountId, projectId, newName } = payload || {};

        if (!accountId || !projectId || !newName) {
          return jsonResponse({ error: '缺少必要参数' }, 400);
        }

        try {
          const serverAccounts = await loadServerAccounts(env, encryptionEnabled);
          const envAccounts = parseEnvAccounts(env);
          const account = pickAccountToken([...envAccounts, ...serverAccounts], accountId);

          if (!account || !account.token) {
            return jsonResponse({ error: '未找到账号或token' }, 404);
          }

          const mutation = `mutation { renameProject(_id: "${projectId}", name: "${newName}") }`;
          const result = await postZeabur(account.token, { query: mutation });

          if (result.data?.renameProject) {
            return jsonResponse({ success: true, message: '项目已重命名' });
          }

          return jsonResponse({ error: '重命名失败', details: result }, 400);
        } catch (error) {
          return jsonResponse({ error: `重命名项目失败: ${error.message}` }, 500);
        }
      }

      return jsonResponse({ error: 'Not Found' }, 404);
    } catch (error) {
      console.error('Worker error:', error);
      return jsonResponse({ error: '服务器错误', details: error.message }, 500);
    }
  }
};

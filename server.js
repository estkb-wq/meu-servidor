const express = require("express");
const cors = require("cors");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;

// =========================
// CONFIG ADMIN
// =========================
const ADMIN_USER = process.env.ADMIN_USER || "admin";
const ADMIN_PASS = process.env.ADMIN_PASS || "123456";

app.use(cors());
app.use(express.json());

const KEYS_FILE = path.join(__dirname, "keys.json");
const DEVICES_FILE = path.join(__dirname, "devices.json");

// =========================
// FUNÇÕES AUXILIARES
// =========================
function ensureFile(filePath, defaultData) {
  if (!fs.existsSync(filePath)) {
    fs.writeFileSync(filePath, JSON.stringify(defaultData, null, 2), "utf8");
  }
}

function readJSON(filePath, fallback = []) {
  try {
    if (!fs.existsSync(filePath)) return fallback;
    const raw = fs.readFileSync(filePath, "utf8").trim();
    if (!raw) return fallback;
    return JSON.parse(raw);
  } catch (error) {
    console.error("Erro ao ler arquivo:", filePath, error);
    return fallback;
  }
}

function saveJSON(filePath, data) {
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2), "utf8");
}

function generateKey() {
  const chars = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

  const block = () =>
    Array.from(
      { length: 4 },
      () => chars[Math.floor(Math.random() * chars.length)]
    ).join("");

  return `ES-${block()}-${block()}-${block()}`;
}

function addDays(days) {
  const date = new Date();
  date.setDate(date.getDate() + days);
  return date.toISOString();
}

function getStatus(keyObj) {
  if (!keyObj) return "desconhecida";

  if (keyObj.revoked) return "revogada";

  if (keyObj.expiresAt && new Date(keyObj.expiresAt) < new Date()) {
    return "expirada";
  }

  if (keyObj.active) return "ativa";

  return "disponível";
}

function isAuthorized(req) {
  const user = req.headers["x-admin-user"];
  const pass = req.headers["x-admin-pass"];
  return user === ADMIN_USER && pass === ADMIN_PASS;
}

function requireAdmin(req, res, next) {
  if (!isAuthorized(req)) {
    return res.status(401).json({
      success: false,
      message: "Não autorizado."
    });
  }

  next();
}

// =========================
// ANTI-BYPASS BÁSICO
// =========================
app.use((req, res, next) => {
  if (
    req.path === "/" ||
    req.path === "/health" ||
    req.path === "/admin" ||
    req.path === "/admin-login"
  ) {
    return next();
  }

  const ua = String(req.headers["user-agent"] || "").toLowerCase();

  // bloqueia ferramentas comuns, mas sem atrapalhar o Electron
  if (ua.includes("postman") || ua.includes("insomnia")) {
    return res.status(403).json({
      success: false,
      message: "Acesso bloqueado."
    });
  }

  next();
});

// =========================
// GARANTIR ARQUIVOS
// =========================
ensureFile(KEYS_FILE, []);
ensureFile(DEVICES_FILE, []);

// =========================
// ROTAS PÚBLICAS
// =========================
app.get("/", (req, res) => {
  res.json({
    success: true,
    status: "online",
    message: "Servidor de licenças rodando"
  });
});

app.get("/health", (req, res) => {
  res.json({
    success: true,
    message: "Servidor online",
    time: new Date().toISOString()
  });
});

app.get("/admin", (req, res) => {
  res.sendFile(path.join(__dirname, "admin.html"));
});

app.post("/admin-login", (req, res) => {
  try {
    const { username, password } = req.body;

    if (username === ADMIN_USER && password === ADMIN_PASS) {
      return res.json({
        success: true,
        message: "Login realizado com sucesso."
      });
    }

    return res.status(401).json({
      success: false,
      message: "Usuário ou senha inválidos."
    });
  } catch (error) {
    console.error("Erro em /admin-login:", error);
    return res.status(500).json({
      success: false,
      message: "Erro ao fazer login."
    });
  }
});

// =========================
// GERAR KEY
// =========================
app.post("/generate-key", requireAdmin, (req, res) => {
  try {
    const days = Math.max(1, Number(req.body.days) || 30);
    const keys = readJSON(KEYS_FILE, []);

    let newKey = generateKey();

    while (keys.some((k) => k.key === newKey)) {
      newKey = generateKey();
    }

    const keyData = {
      id: crypto.randomUUID(),
      key: newKey,
      createdAt: new Date().toISOString(),
      expiresAt: addDays(days),
      active: false,
      usedBy: null,
      activatedAt: null,
      revoked: false
    };

    keys.push(keyData);
    saveJSON(KEYS_FILE, keys);

    return res.json({
      success: true,
      message: "Key gerada com sucesso.",
      keyData: {
        ...keyData,
        status: getStatus(keyData)
      }
    });
  } catch (error) {
    console.error("Erro em /generate-key:", error);
    return res.status(500).json({
      success: false,
      message: "Erro ao gerar key."
    });
  }
});

// =========================
// ATIVAR KEY
// =========================
app.post("/activate-key", (req, res) => {
  try {
    const { key, deviceId } = req.body;

    if (!key || !deviceId) {
      return res.status(400).json({
        success: false,
        message: "Key e deviceId são obrigatórios."
      });
    }

    const keys = readJSON(KEYS_FILE, []);
    const devices = readJSON(DEVICES_FILE, []);

    const foundKey = keys.find((k) => k.key === key);

    if (!foundKey) {
      return res.status(404).json({
        success: false,
        message: "Key não encontrada."
      });
    }

    if (foundKey.revoked) {
      return res.status(403).json({
        success: false,
        message: "Essa key foi revogada."
      });
    }

    if (foundKey.expiresAt && new Date(foundKey.expiresAt) < new Date()) {
      return res.status(403).json({
        success: false,
        message: "Key expirada."
      });
    }

    if (foundKey.active && foundKey.usedBy && foundKey.usedBy !== deviceId) {
      return res.status(403).json({
        success: false,
        message: "Essa key já está em uso em outro dispositivo."
      });
    }

    foundKey.active = true;
    foundKey.usedBy = deviceId;
    foundKey.activatedAt = foundKey.activatedAt || new Date().toISOString();

    const existingDevice = devices.find((d) => d.deviceId === deviceId);

    if (!existingDevice) {
      devices.push({
        deviceId,
        key,
        activatedAt: new Date().toISOString()
      });
    } else {
      existingDevice.key = key;
      existingDevice.activatedAt =
        existingDevice.activatedAt || new Date().toISOString();
    }

    saveJSON(KEYS_FILE, keys);
    saveJSON(DEVICES_FILE, devices);

    return res.json({
      success: true,
      message: "Key ativada com sucesso.",
      data: {
        key: foundKey.key,
        deviceId,
        expiresAt: foundKey.expiresAt,
        activatedAt: foundKey.activatedAt,
        status: getStatus(foundKey)
      }
    });
  } catch (error) {
    console.error("Erro em /activate-key:", error);
    return res.status(500).json({
      success: false,
      message: "Erro ao ativar key."
    });
  }
});

// =========================
// VERIFICAR ACESSO
// =========================
app.post("/check-access", (req, res) => {
  try {
    const { key, deviceId } = req.body;

    if (!key || !deviceId) {
      return res.status(400).json({
        success: false,
        message: "Key e deviceId são obrigatórios."
      });
    }

    const keys = readJSON(KEYS_FILE, []);
    const foundKey = keys.find((k) => k.key === key);

    if (!foundKey) {
      return res.status(404).json({
        success: false,
        message: "Key inválida."
      });
    }

    if (foundKey.revoked) {
      return res.status(403).json({
        success: false,
        message: "Essa key foi revogada."
      });
    }

    if (!foundKey.active) {
      return res.status(403).json({
        success: false,
        message: "Key ainda não foi ativada."
      });
    }

    if (foundKey.expiresAt && new Date(foundKey.expiresAt) < new Date()) {
      return res.status(403).json({
        success: false,
        message: "Key expirada."
      });
    }

    if (foundKey.usedBy !== deviceId) {
      return res.status(403).json({
        success: false,
        message: "Essa key pertence a outro dispositivo."
      });
    }

    return res.json({
      success: true,
      message: "Acesso liberado.",
      data: {
        key: foundKey.key,
        deviceId,
        expiresAt: foundKey.expiresAt,
        activatedAt: foundKey.activatedAt,
        status: getStatus(foundKey)
      }
    });
  } catch (error) {
    console.error("Erro em /check-access:", error);
    return res.status(500).json({
      success: false,
      message: "Erro ao verificar acesso."
    });
  }
});

// =========================
// LISTAR KEYS
// =========================
app.get("/keys", requireAdmin, (req, res) => {
  try {
    const keys = readJSON(KEYS_FILE, []);
    const mapped = keys
      .map((k) => ({
        ...k,
        status: getStatus(k)
      }))
      .sort((a, b) => new Date(b.createdAt) - new Date(a.createdAt));

    return res.json({
      success: true,
      total: mapped.length,
      keys: mapped
    });
  } catch (error) {
    console.error("Erro em /keys:", error);
    return res.status(500).json({
      success: false,
      message: "Erro ao listar keys."
    });
  }
});

// =========================
// REVOGAR KEY
// =========================
app.post("/revoke-key", requireAdmin, (req, res) => {
  try {
    const { key } = req.body;

    if (!key) {
      return res.status(400).json({
        success: false,
        message: "Informe a key."
      });
    }

    const keys = readJSON(KEYS_FILE, []);
    const foundKey = keys.find((k) => k.key === key);

    if (!foundKey) {
      return res.status(404).json({
        success: false,
        message: "Key não encontrada."
      });
    }

    foundKey.revoked = true;
    saveJSON(KEYS_FILE, keys);

    return res.json({
      success: true,
      message: "Key revogada com sucesso.",
      key: {
        ...foundKey,
        status: getStatus(foundKey)
      }
    });
  } catch (error) {
    console.error("Erro em /revoke-key:", error);
    return res.status(500).json({
      success: false,
      message: "Erro ao revogar key."
    });
  }
});

// =========================
// REATIVAR KEY
// =========================
app.post("/reactivate-key", requireAdmin, (req, res) => {
  try {
    const { key } = req.body;

    if (!key) {
      return res.status(400).json({
        success: false,
        message: "Informe a key."
      });
    }

    const keys = readJSON(KEYS_FILE, []);
    const foundKey = keys.find((k) => k.key === key);

    if (!foundKey) {
      return res.status(404).json({
        success: false,
        message: "Key não encontrada."
      });
    }

    foundKey.revoked = false;
    saveJSON(KEYS_FILE, keys);

    return res.json({
      success: true,
      message: "Key reativada com sucesso.",
      key: {
        ...foundKey,
        status: getStatus(foundKey)
      }
    });
  } catch (error) {
    console.error("Erro em /reactivate-key:", error);
    return res.status(500).json({
      success: false,
      message: "Erro ao reativar key."
    });
  }
});

// =========================
// INICIAR SERVIDOR
// =========================
app.listen(PORT, () => {
  console.log(`Servidor rodando na porta ${PORT}`);
});

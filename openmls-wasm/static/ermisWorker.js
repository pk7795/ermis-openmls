class ErmisWorker {
  constructor() {
    this.worker = new Worker(new URL("./worker.js", import.meta.url), {
      type: "module",
    });
    this.callbacks = new Map();

    this.worker.onmessage = (event) => {
      if (event.data.type === "wasmReady") {
        console.log("ErmisWorker: WASM loaded in worker");
      }
      const { requestId, type, result, message } = event.data;
      if (this.callbacks.has(requestId)) {
        const { resolve, reject } = this.callbacks.get(requestId);
        this.callbacks.delete(requestId);
        if (type === "success") {
          resolve(result);
        } else {
          reject(new Error(message));
        }
      }
    };
  }

  generateUUID() {
    return "xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx".replace(
      /[xy]/g,
      function (c) {
        var r = (Math.random() * 16) | 0,
          v = c == "x" ? r : (r & 0x3) | 0x8;
        return v.toString(16);
      }
    );
  }

  // const uuid = (crypto.randomUUID && window.isSecureContext) ? crypto.randomUUID() : generateUUID();
  // console.log(uuid);

  sendMessage(type, data) {
    return new Promise((resolve, reject) => {
      // const requestId = crypto.randomUUID();
      const requestId =
        crypto.randomUUID && window.isSecureContext
          ? crypto.randomUUID()
          : this.generateUUID();
      this.callbacks.set(requestId, { resolve, reject });

      this.worker.postMessage({ requestId, type, ...data });
    });
  }

  async createClient(db, encryptionKey, accountAddress, clientName, apiEnv) {
    return this.sendMessage("createClient", {
      db,
      encryptionKey,
      accountAddress,
      clientName,
      apiEnv,
    });
  }

  async keyPackage(clientName) {
    return this.sendMessage("keyPackage", { clientName });
  }

  async createWithGroupIdAndMembers(clientName, groupId, memberKeyPackages) {
    return this.sendMessage("createWithGroupIdAndMembers", {
      clientName,
      groupId,
      memberKeyPackages,
    });
  }

  async encryptMessage(clientName, groupId, message) {
    return this.sendMessage("encryptMessage", { clientName, groupId, message });
  }

  async processIncomingMessage(clientName, groupId, incomingMessage, sender) {
    console.log("ErmisWorker: start processMessage");
    return this.sendMessage("processMessage", {
      clientName,
      groupId,
      incomingMessage,
      sender,
    });
  }

  async processWelcomeMessage(clientName, groupId, message) {
    console.log(
      "ErmisWorker: processWelcomeMessage",
      clientName,
      groupId,
      message
    );
    return this.sendMessage("processWelcomeMessage", {
      clientName,
      groupId,
      message,
    });
  }

  async joinGroupByWelcome(clientName, groupId) {
    return this.sendMessage("joinGroupByWelcome", { clientName, groupId });
  }

  // #[wasm_bindgen(js_name = getEpoch)]
  // pub fn get_epoch(&self, group_id: &str) -> Result<u64, JsError> {

  async getEpoch(clientName, groupId) {
    return this.sendMessage("getEpoch", { clientName, groupId });
  }

  async uploadKeypackage(clientName) {
    return this.sendMessage("uploadKeypackage", { clientName });
  }

  async fetchKeypackage(clientName, userNames) {
    return this.sendMessage("fetchKeyPackages", { clientName, userNames });
  }

  // pub fn get_group_messages(&self, group_id: &str) -> Result<Vec<FfiMessage>, JsError> {
  async getGroupMessages(clientName, groupId) {
    return this.sendMessage("getGroupMessages", { clientName, groupId });
  }

  async addMembers(clientName, groupId, membersKeyPackages) {
    return this.sendMessage("addMembers", {
      clientName,
      groupId,
      membersKeyPackages,
    });
  }

  async createGroup(clientName, groupId) {
    return this.sendMessage("createGroup", { clientName, groupId });
  }

  async createMessage(clientName, groupId, content) {
    return this.sendMessage("createMessage", { clientName, groupId, content });
  }

  async dbReconnect(clientName) {
    return this.sendMessage("dbReconnect", { clientName });
  }

  async exportGroupRatchetTree(clientName, groupId) {
    return this.sendMessage("exportGroupRatchetTree", { clientName, groupId });
  }

  async getWelcomeMessage(clientName, groupId) {
    return this.sendMessage("getWelcomeMessage", { clientName, groupId });
  }

  async leaveGroup(clientName, groupId) {
    return this.sendMessage("leaveGroup", { clientName, groupId });
  }

  async loadGroup(clientName, groupId) {
    return this.sendMessage("loadGroup", { clientName, groupId });
  }

  async memberCount(clientName, groupId) {
    return this.sendMessage("memberCount", { clientName, groupId });
  }

  async releaseDbConnection(clientName) {
    return this.sendMessage("releaseDbConnection", { clientName });
  }

  async removeMember(clientName, groupId, member) {
    return this.sendMessage("removeMember", { clientName, groupId, member });
  }
}

export default new ErmisWorker();

import init, { create_new } from "../pkg/openmls_wasm.js";
// store clients in an object
let clients = {};

(async () => {
  console.log("Worker.js: initializing wasm");
  await init();
  postMessage({ type: "wasmReady" });
})();

self.onmessage = async (event) => {
  const { requestId, clientName, type, ...data } = event.data;
  console.log("-----------------worker command type--------------", type);
  try {
    switch (type) {
      case "createClient": {
        const client = await create_new(
          data.db,
          data.encryptionKey,
          data.accountAddress,
          clientName,
          data.apiEnv
        );
        clients[clientName] = client;
        const result = {
          isIdentityExist: client.isIdentityExist,
        };
        postMessage({ type: "success", requestId, result });
        break;
      }

      case "createWithGroupIdAndMembers": {
        if (!clients[clientName]) {
          throw new Error("client has not been created yet");
        }
        const client = clients[clientName];
        const res = client.createWithGroupIdAndMembers(
          data.groupId,
          data.memberKeyPackages
        );
        const result = {
          commit: res.commit,
          welcome: res.welcome,
          proposal: res.proposal,
          // ratchetTree: res.ratchetTree,
        };
        postMessage({ type: "success", requestId, result });
        break;
      }

      case "keyPackage": {
        if (!clients[clientName]) {
          throw new Error("client has not been created yet");
        }
        const client = clients[clientName];
        const result = client.keyPackage();
        postMessage({ type: "success", requestId, result });
        break;
      }

      case "encryptMessage": {
        console.log("Worker.js: encryptMessage", data.message);
        if (!clients[clientName]) {
          throw new Error("client", clientName, " has not been created yet");
        }
        const client = clients[clientName];
        const res = client.encryptMessage(data.groupId, data.message);
        console.log("Worker.js: wasm createMessage result", res);
        const result = {
          encryptedMessage: res.encryptedMessage,
        };

        postMessage({ type: "success", requestId, result });
        break;
      }

      case "processMessage": {
        console.log("Worker.js: processMessage", data);
        if (!clients[clientName]) {
          throw new Error("client has not been created yet");
        }
        const client = clients[clientName];
        console.log("Size of message:", data.incomingMessage.length);
        const res = client.processMessage(
          data.groupId,
          data.incomingMessage,
          data.sender
        );

        console.log("---------- process message done----------");
        const result = {
          decryptedMessage: res.decryptedMessage,
          messageType: res.messageType,
        };
        console.log("Worker.js: processMessage result", result);
        postMessage({ type: "success", requestId, result });
        break;
      }

      case "processWelcomeMessage": {
        if (!clients[clientName]) {
          throw new Error(`client ${clientName} has not been created yet`);
        }
        const client = clients[clientName];
        const result = await client.processWelcomeMessage(
          data.message,
          data.groupId
        );
        postMessage({ type: "success", requestId, result });
        break;
      }

      case "joinGroupByWelcome": {
        if (!clients[clientName]) {
          throw new Error("client has not been created yet");
        }
        const client = clients[clientName];
        const result = client.joinGroupByWelcome(data.groupId);
        postMessage({ type: "success", requestId, result });
        break;
      }

      case "getEpoch": {
        if (!clients[clientName]) {
          throw new Error("client has not been created yet");
        }
        const client = clients[clientName];
        const result = client.getEpoch(data.groupId);
        postMessage({ type: "success", requestId, result });
        break;
      }

      case "uploadKeypackage": {
        if (!clients[clientName]) {
          throw new Error("client has not been created yet");
        }
        const client = clients[clientName];
        const result = await client.uploadKeypackage();
        postMessage({ type: "success", requestId, result });
        break;
      }

      case "fetchKeyPackages": {
        if (!clients[clientName]) {
          throw new Error("client has not been created yet");
        }
        const client = clients[clientName];
        const result = await client.fetchKeyPackages(data.userNames);
        postMessage({ type: "success", requestId, result });
        break;
      }
      case "getGroupMessages": {
        if (!clients[clientName]) {
          throw new Error("client has not been created yet");
        }
        const client = clients[clientName];
        const res = await client.getGroupMessages(data.groupId);
        const result = [];
        for (const message of res) {
          const mess = {
            id: message.id,
            cid: message.cid,
            text: message.text,
            createdAt: message.created_at,
            senderId: message.sender_id,
            messageType: message.message_type,
          };
          result.push(mess);
        }
        postMessage({ type: "success", requestId, result });
        break;
      }
      //   pub struct FfiMessage {
      //     pub id: String,
      //     pub cid: String,
      //     pub text: String,
      //     pub created_at: String,
      //     pub sender_id: String,
      //     pub message_type: String,
      // }

      //-------------------- add more cases here -------------------//

      case "addMembers": {
        if (!clients[clientName]) {
          throw new Error("client has not been created yet");
        }
        const client = clients[clientName];
        const res = client.addMembers(data.groupId, data.membersKeyPackages);
        const result = {
          commit: res.commit,
          welcome: res.welcome,
          proposal: res.proposal,
        };
        postMessage({ type: "success", requestId, result });
        break;
      }

      case "createGroup": {
        if (!clients[clientName]) {
          throw new Error("client has not been created yet");
        }
        const client = clients[clientName];
        const result = client.createGroup(data.groupId);
        postMessage({ type: "success", requestId, result });
        break;
      }

      case "dbReconnect": {
        if (!clients[clientName]) {
          throw new Error("client has not been created yet");
        }
        const client = clients[clientName];
        await client.dbReconnect();
        postMessage({ type: "success", requestId });
        break;
      }

      case "exportGroupRatchetTree": {
        if (!clients[clientName]) {
          throw new Error("client has not been created yet");
        }
        const client = clients[clientName];
        const result = client.exportGroupRatchetTree(data.groupId);
        postMessage({ type: "success", requestId, result });
        break;
      }

      case "getWelcomeMessage": {
        if (!clients[clientName]) {
          throw new Error("client has not been created yet");
        }
        const client = clients[clientName];
        const result = client.getWelcomeMessage(data.groupId);
        postMessage({ type: "success", requestId, result });
        break;
      }

      case "leaveGroup": {
        if (!clients[clientName]) {
          throw new Error("client has not been created yet");
        }
        const client = clients[clientName];
        const result = client.leaveGroup(data.groupId);
        postMessage({ type: "success", requestId, result });
        break;
      }

      case "loadGroup": {
        if (!clients[clientName]) {
          throw new Error("client has not been created yet");
        }
        const client = clients[clientName];
        const result = client.loadGroup(data.groupId);
        postMessage({ type: "success", requestId, result });
        break;
      }

      case "memberCount": {
        if (!clients[clientName]) {
          throw new Error("client has not been created yet");
        }
        const client = clients[clientName];
        const result = client.memberCount(data.groupId);
        postMessage({ type: "success", requestId, result });
        break;
      }

      case "releaseDbConnection": {
        if (!clients[clientName]) {
          throw new Error("client has not been created yet");
        }
        const client = clients[clientName];
        client.releaseDbConnection();
        postMessage({ type: "success", requestId });
        break;
      }

      case "removeMember": {
        if (!clients[clientName]) {
          throw new Error("client has not been created yet");
        }
        const client = clients[clientName];
        const result = client.removeMember(data.groupId, data.member);
        postMessage({ type: "success", requestId, result });
        break;
      }

      default:
        postMessage({
          type: "error",
          message: `Unknown request type: ${type}`,
        });
        break;
    }
  } catch (err) {
    postMessage({ type: "error", requestId, message: err.message });
  }
};

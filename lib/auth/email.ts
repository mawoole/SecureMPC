type EmailRuntime = {
  RESEND_API_KEY?: unknown;
  TRUSTMAP_EMAIL_FROM?: unknown;
  TRUSTMAP_DEV_EMAIL_LOG?: unknown;
};

type TransactionalEmail = {
  subject: string;
  text: string;
  to: string;
};

function runtimeString(value: unknown): string {
  return typeof value === "string" ? value.trim() : "";
}

export async function sendTransactionalEmail(
  runtime: EmailRuntime,
  message: TransactionalEmail,
): Promise<void> {
  const apiKey = runtimeString(runtime.RESEND_API_KEY);
  const from = runtimeString(runtime.TRUSTMAP_EMAIL_FROM);
  const developmentLog =
    runtimeString(runtime.TRUSTMAP_DEV_EMAIL_LOG).toLowerCase() === "true";

  if (!apiKey || !from) {
    if (developmentLog) {
      console.info(
        `[MCP TrustMap email local] ${message.subject} -> ${message.to}\n${message.text}`,
      );
      return;
    }
    throw new Error(
      "Le service d’e-mail transactionnel n’est pas configuré.",
    );
  }

  const response = await fetch("https://api.resend.com/emails", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${apiKey}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      from,
      to: [message.to],
      subject: message.subject,
      text: message.text,
    }),
  });
  if (!response.ok) {
    throw new Error(`Échec de l’envoi de l’e-mail (${response.status}).`);
  }
}

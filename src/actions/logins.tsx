"use server";
import { LoginSchema } from "@/schema";
import { signIn } from "@/auth";
import { DEFAULT_LOGIN_REDIRECT } from "@/routes";
import { AuthError } from "next-auth";
import { db } from "@/lib/db";
import { getUserByEmail } from "@/data/user";
import { getVerificationTokenByEmail } from "@/data/verification-token";
import {
  generateTwoFactorToken,
  generateVerificationToken,
} from "@/lib/tokens";
import { sendTwoFactorTokenEmail, sendVerificationEmail } from "@/lib/mail";
import { getTwoFactorTokenByEmail } from "@/data/two-factor-token";
import { getTwoFactorConfirmationByUserId } from "@/data/two-factor-confirmation";
import { cookies } from "next/headers";

export const login = async (data) => {
  const cookieStore = cookies();
  const callbackUrlCokie = cookieStore.get("callback-url");
  const callbackUrl = callbackUrlCokie?.value || "/user";
  const validatedFields = LoginSchema.safeParse(data);
  if (!validatedFields.success) {
    return { error: "Entré invalide" };
  }
  const { email, password, code } = validatedFields.data;
  const existingUser = await getUserByEmail(email);
  if (existingUser && existingUser.email && !existingUser.password) {
    return { error: "Connectez-vous avec google ou github" };
  }
  if (!existingUser || !existingUser.email || !existingUser.password) {
    return { error: "Cet a address mail n'existe pas" };
  }
  // if (!existingUser.emailVerified) {
  //   const verificationToken = await generateVerificationToken(
  //     existingUser.email
  //   );
  //   await sendVerificationEmail(
  //     verificationToken.email,
  //     verificationToken.token
  //   );
  //   return { success: "Email de confirmation envoyé!" };
  // }
  if (existingUser.isTwoFactorEnabled && existingUser.email) {
    if (code) {
      const twoFactorToken = await getTwoFactorTokenByEmail(existingUser.email);
      if (!twoFactorToken) {
        return { error: "code invalide" };
      }
      if (twoFactorToken.token != code) {
        return { error: "code invalide" };
      }
      const hasExpired = new Date(twoFactorToken.expires) < new Date();
      console.log({ hasExpired });
      if (hasExpired) {
        return { error: "code expiré" };
      }
      await db.twoFactorToken.delete({
        where: {
          id: twoFactorToken.id,
        },
      });
      const existingConfirmation = await getTwoFactorConfirmationByUserId(
        existingUser.id
      );
      console.log({ existingConfirmation });
      if (existingConfirmation) {
        await db.twoFactorConfirmation.delete({
          where: { id: existingConfirmation.id },
        });
      }
      await db.twoFactorConfirmation.create({
        data: {
          userId: existingUser.id,
        },
      });
    } else {
      const twoFactorToken = await generateTwoFactorToken(existingUser.email);
      await sendTwoFactorTokenEmail(twoFactorToken.email, twoFactorToken.token);
      return { twoFactor: true };
    }
  }
  try {
    await signIn("credentials", {
      email,
      password,
      redirectTo: callbackUrl || DEFAULT_LOGIN_REDIRECT,
    });
  } catch (error) {
    if (error instanceof AuthError) {
      switch (error.type) {
        case "CredentialsSignin":
          return { error: "Identifiants Invalides" };
        default:
          return { error: "Erreur Inconue" };
      }
    }
    throw error;
  }
  return { success: "email envoyé" };
};

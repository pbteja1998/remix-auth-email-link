import type { SessionStorage } from '@remix-run/server-runtime'
import { redirect } from '@remix-run/server-runtime'
import crypto from 'crypto-js'
import type { AuthenticateOptions, StrategyVerifyCallback } from 'remix-auth'
import { Strategy } from 'remix-auth'

export type SendEmailOptions<User> = {
  emailAddress: string
  magicLink: string
  user?: User | null
  domainUrl: string
  form: FormData
}

export type SendEmailFunction<User> = {
  (options: SendEmailOptions<User>): Promise<void>
}

/**
 * Validate the email address the user is trying to use to login.
 * This can be useful to ensure it's not a disposable email address.
 * @param emailAddress The email address to validate
 */
export type VerifyEmailFunction = {
  (email: string): Promise<void>
}

/**
 * The content of the magic link payload
 */
export type MagicLinkPayload = {
  /**
   * The email address used to authenticate
   */
  emailAddress: string
  form: Record<string, unknown>
  /**
   * When the magic link was created, as an ISO string. This is used to check
   * the email link is still valid.
   */
  creationDate: string
  /**
   * If it should be validated or not.
   */
  validateSessionMagicLink: boolean
}

/**
 * This interface declares what configuration the strategy needs from the
 * developer to correctly work.
 */
export type EmailLinkStrategyOptions<User> = {
  /**
   * The endpoint the user will go after clicking on the email link.
   * A whole URL is not required, the pathname is enough, the strategy will
   * detect the host of the request and use it to build the URL.
   * @default "/magic"
   */
  callbackURL?: string
  /**
   * A function to send the email. This function should receive the email
   * address of the user and the URL to redirect to and should return a Promise.
   * The value of the Promise will be ignored.
   */
  sendEmail: SendEmailFunction<User>
  /**
   * A function to validate the email address. This function should receive the
   * email address as a string and return a Promise. The value of the Promise
   * will be ignored, in case of error throw an error.
   *
   * By default it only test the email against the RegExp `/.+@.+/`.
   */
  verifyEmailAddress?: VerifyEmailFunction
  /**
   * A secret string used to encrypt and decrypt the token and magic link.
   */
  secret: string
  /**
   * The name of the form input used to get the email.
   * @default "email"
   */
  emailField?: string
  /**
   * The param name the strategy will use to read the token from the email link.
   * @default "token"
   */
  magicLinkSearchParam?: string
  /**
   * How long the magic link will be valid. Default to 30 minutes.
   * @default 1_800_000
   */
  linkExpirationTime?: number
  /**
   * The key on the session to store any error message.
   * @default "auth:error"
   */
  sessionErrorKey?: string
  /**
   * The key on the session to store the magic link.
   * @default "auth:magicLink"
   */
  sessionMagicLinkKey?: string
  /**
   * Add an extra layer of protection and validate the magic link is valid.
   * @default false
   */
  validateSessionMagicLink?: boolean

  /**
   * The key on the session to store the email.
   * It's unset the same time the sessionMagicLinkKey is.
   * @default "auth:email"
   */
  sessionEmailKey?: string
}

/**
 * This interface declares what the developer will receive from the strategy
 * to verify the user identity in their system.
 */
export type EmailLinkStrategyVerifyParams = {
  email: string
  form: FormData
  /**
   * True, if the verify callback is called after clicking on the magic link
   */
  magicLinkVerify: boolean
}

const verifyEmailAddress: VerifyEmailFunction = async (email) => {
  if (!/.+@.+/u.test(email)) {
    throw new Error('A valid email is required.')
  }
}

export class EmailLinkStrategy<User> extends Strategy<
  User,
  EmailLinkStrategyVerifyParams
> {
  public name = 'email-link'

  private readonly emailField: string = 'email'

  private readonly callbackURL: string

  private readonly sendEmail: SendEmailFunction<User>

  private readonly validateEmail: VerifyEmailFunction

  private readonly secret: string

  private readonly magicLinkSearchParam: string

  private readonly linkExpirationTime: number

  private readonly sessionErrorKey: string

  private readonly sessionMagicLinkKey: string

  private readonly validateSessionMagicLink: boolean

  private readonly sessionEmailKey: string

  constructor(
    options: EmailLinkStrategyOptions<User>,
    verify: StrategyVerifyCallback<User, EmailLinkStrategyVerifyParams>
  ) {
    super(verify)
    this.sendEmail = options.sendEmail
    this.callbackURL = options.callbackURL ?? '/magic'
    this.secret = options.secret
    this.sessionErrorKey = options.sessionErrorKey ?? 'auth:error'
    this.sessionMagicLinkKey = options.sessionMagicLinkKey ?? 'auth:magiclink'
    this.validateEmail = options.verifyEmailAddress ?? verifyEmailAddress
    this.emailField = options.emailField ?? this.emailField
    this.magicLinkSearchParam = options.magicLinkSearchParam ?? 'token'
    this.linkExpirationTime = options.linkExpirationTime ?? 1000 * 60 * 30 // 30 minutes
    this.validateSessionMagicLink = options.validateSessionMagicLink ?? false
    this.sessionEmailKey = options.sessionEmailKey ?? 'auth:email'
  }

  public async authenticate(
    request: Request,
    sessionStorage: SessionStorage,
    options: AuthenticateOptions
  ): Promise<User> {
    const session = await sessionStorage.getSession(
      request.headers.get('Cookie')
    )

    const form = new URLSearchParams(await request.text())

    // This should only be called in an action if it's used to start the login process
    if (request.method === 'POST') {
      if (!options.successRedirect) {
        throw new Error(
          'Missing successRedirect. The successRedirect is required for POST requests.'
        )
      }

      // get the email address from the request body
      const emailAddress = form.get(this.emailField)

      // if it doesn't have an email address,
      if (!emailAddress || typeof emailAddress !== 'string') {
        const message = 'Missing email address.'
        if (!options.failureRedirect) {
          throw new Error(message)
        }
        session.flash(this.sessionErrorKey, { message })
        const cookie = await sessionStorage.commitSession(session)
        throw redirect(options.failureRedirect, {
          headers: { 'Set-Cookie': cookie },
        })
      }

      try {
        // Validate the email address
        await this.validateEmail(emailAddress)

        const domainUrl = this.getDomainURL(request)

        const magicLink = await this.sendToken(emailAddress, domainUrl, form)

        session.set(this.sessionMagicLinkKey, await this.encrypt(magicLink))
        session.set(this.sessionEmailKey, emailAddress)

        throw redirect(options.successRedirect, {
          headers: {
            'Set-Cookie': await sessionStorage.commitSession(session),
          },
        })
      } catch (error) {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        if ((error as any).status === 302) {
          // If it's a redirect, then just throw the redirect as it is
          throw error
        }
        if (!options.failureRedirect) {
          throw error
        }
        const { message } = error as Error
        session.flash(this.sessionErrorKey, { message })
        const cookie = await sessionStorage.commitSession(session)
        throw redirect(options.failureRedirect, {
          headers: { 'Set-Cookie': cookie },
        })
      }
    }

    let user: User

    try {
      // If we get here, the user clicked on the magic link inside email
      const magicLink = session.get(this.sessionMagicLinkKey) ?? ''
      const { emailAddress: email, form } = await this.validateMagicLink(
        request.url,
        await this.decrypt(magicLink)
      )
      // now that we have the user email we can call verify to get the user
      user = await this.verify({ email, form, magicLinkVerify: true })
    } catch (error) {
      // if something happens, we should redirect to the failureRedirect
      // and flash the error message, or just throw the error if failureRedirect
      // is not defined
      if (!options.failureRedirect) {
        throw error
      }
      const { message } = error as Error
      session.flash(this.sessionErrorKey, { message })
      const cookie = await sessionStorage.commitSession(session)
      throw redirect(options.failureRedirect, {
        headers: { 'Set-Cookie': cookie },
      })
    }

    if (!options.successRedirect) {
      return user
    }

    // remove the magic link and email from the session
    session.unset(this.sessionMagicLinkKey)
    session.unset(this.sessionEmailKey)

    session.set(options.sessionKey, user)
    const cookie = await sessionStorage.commitSession(session)
    throw redirect(options.successRedirect, {
      headers: { 'Set-Cookie': cookie },
    })
  }

  public async getMagicLink(
    emailAddress: string,
    domainUrl: string,
    form: FormData
  ): Promise<string> {
    const payload = this.createMagicLinkPayload(emailAddress, form)
    const stringToEncrypt = JSON.stringify(payload)
    const encryptedString = await this.encrypt(stringToEncrypt)
    const url = new URL(domainUrl)
    url.pathname = this.callbackURL
    url.searchParams.set(this.magicLinkSearchParam, encryptedString)
    return url.toString()
  }

  private getDomainURL(request: Request): string {
    const host =
      request.headers.get('X-Forwarded-Host') ?? request.headers.get('host')

    if (!host) {
      throw new Error('Could not determine domain URL.')
    }

    const protocol =
      request.headers.get('X-Forwarded-Proto') ??
      (host.includes('localhost') || host.includes('127.0.0.1')
        ? 'http'
        : 'https')

    return `${protocol}://${host}`
  }

  private async sendToken(email: string, domainUrl: string, form: FormData) {
    const magicLink = await this.getMagicLink(email, domainUrl, form)

    const user = await this.verify({
      email,
      form,
      magicLinkVerify: false,
    }).catch(() => null)

    await this.sendEmail({
      emailAddress: email,
      magicLink,
      user,
      domainUrl,
      form,
    })

    return magicLink
  }

  private createMagicLinkPayload(
    emailAddress: string,
    form: FormData
  ): MagicLinkPayload {
    return {
      emailAddress,
      form: Object.fromEntries(
        [...form.keys()].map((key) => [
          key,
          form.getAll(key).length > 1 ? form.getAll(key) : form.get(key),
        ])
      ),
      creationDate: new Date().toISOString(),
      validateSessionMagicLink: this.validateSessionMagicLink,
    }
  }

  private async encrypt(value: string): Promise<string> {
    return crypto.AES.encrypt(value, this.secret).toString()
  }

  private async decrypt(value: string): Promise<string> {
    const bytes = crypto.AES.decrypt(value, this.secret)
    return bytes.toString(crypto.enc.Utf8)
  }

  private getMagicLinkCode(link: string) {
    try {
      const url = new URL(link)
      return url.searchParams.get(this.magicLinkSearchParam) ?? ''
    } catch {
      return ''
    }
  }

  private async validateMagicLink(
    requestUrl: string,
    sessionMagicLink?: string
  ) {
    const linkCode = this.getMagicLinkCode(requestUrl)
    const sessionLinkCode = sessionMagicLink
      ? this.getMagicLinkCode(sessionMagicLink)
      : null

    let emailAddress
    let linkCreationDateString
    let validateSessionMagicLink
    let form: Record<string, unknown>
    try {
      const decryptedString = await this.decrypt(linkCode)
      const payload = JSON.parse(decryptedString) as MagicLinkPayload
      emailAddress = payload.emailAddress
      form = payload.form
      linkCreationDateString = payload.creationDate
      validateSessionMagicLink = payload.validateSessionMagicLink
    } catch (error: unknown) {
      console.error(error)
      throw new Error('Sign in link invalid. Please request a new one.')
    }

    if (typeof emailAddress !== 'string') {
      throw new TypeError('Sign in link invalid. Please request a new one.')
    }

    if (validateSessionMagicLink) {
      if (!sessionLinkCode) {
        throw new Error('Sign in link invalid. Please request a new one.')
      }
      if (linkCode !== sessionLinkCode) {
        throw new Error(
          `You must open the magic link on the same device it was created from for security reasons. Please request a new link.`
        )
      }
    }

    if (typeof linkCreationDateString !== 'string') {
      throw new TypeError('Sign in link invalid. Please request a new one.')
    }

    const linkCreationDate = new Date(linkCreationDateString)
    const expirationTime = linkCreationDate.getTime() + this.linkExpirationTime
    if (Date.now() > expirationTime) {
      throw new Error('Magic link expired. Please request a new one.')
    }
    const formData = new FormData()
    Object.keys(form).forEach((key) => {
      if (Array.isArray(form[key])) {
        ;(form[key] as unknown[]).forEach((value) => {
          formData.append(key, value as string | Blob)
        })
      } else {
        formData.append(key, form[key] as string | Blob)
      }
    })
    return { emailAddress, form: formData }
  }
}

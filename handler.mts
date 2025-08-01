import crypto from 'node:crypto'
import {SSMClient, GetParameterCommand} from '@aws-sdk/client-ssm'
import type {LambdaFunctionURLEvent, LambdaFunctionURLResult} from 'aws-lambda'
import userMapJson from './usermap.json' with {type: 'json'}

const ssm = new SSMClient({})

async function getParameterValue(parameterName: string): Promise<string> {
  const command = new GetParameterCommand({
    Name: parameterName,
    WithDecryption: true
  })
  const response = await ssm.send(command)
  const value = response.Parameter?.Value
  if (!value) {
    throw new Error(`SSM Parameter not found or empty: ${parameterName}`)
  }
  return value
}

export async function handle(
  event: LambdaFunctionURLEvent
): Promise<LambdaFunctionURLResult> {
  const userMap: Record<string, string> = userMapJson.usermap
  const convertName = (body: string): string => {
    return body.replace(/@([a-zA-Z0-9_\-]+)/g, function (m, m2) {
      if (userMap[m2]) {
        return `<@${userMap[m2]}>`
      } else {
        return m
      }
    })
  }

  const link = function (url: string, text: string): string {
    return '<' + url + '|' + text + '>'
  }

  // Get secrets from SSM Parameter Store
  const githubWebhookSecretParamName =
    process.env.GITHUB_WEBHOOK_SECRET_PARAMETER_NAME!
  const webhookSecret = await getParameterValue(githubWebhookSecretParamName)

  const signature256 =
    'sha256=' +
    crypto
      .createHmac('sha256', webhookSecret)
      .update(event.body ?? '', 'utf8')
      .digest('hex')

  if (event.headers['x-hub-signature-256'] !== signature256) {
    return {
      statusCode: 401,
      body: 'signature issue'
    }
  }

  const msg = JSON.parse(event.body!)
  const eventName = event.headers['x-github-event']
  let text = ''

  switch (eventName) {
    case 'issue_comment':
    case 'pull_request_review_comment':
      const comment = msg.comment
      text += comment.user.login + ': \n'
      text += convertName(comment.body) + '\n'
      text += comment.html_url
      break
    case 'pull_request_review':
      const review = msg.review
      text += review.user.login + ': \n'
      text += convertName(review.body) + '\n'
      text += review.html_url
      break
    case 'issues':
      const issue = msg.issue
      if (msg.action === 'opended' || msg.action === 'closed') {
        text += 'Issue ' + msg.action + '\n'
        text += link(issue.html_url, issue.title)
      }
      break
    case 'push':
      text += 'Pushed' + '\n'
      text += msg.compare + '\n'
      for (let i = 0; i < msg.commits.length; i++) {
        const commit = msg.commits[i]
        text +=
          link(commit.url, commit.id.substr(0, 8)) +
          ' ' +
          commit.message +
          ' - ' +
          commit.author.name +
          '\n'
      }
      break
    case 'pull_request':
      const pull_request = msg.pull_request
      if (msg.action === 'opended' || msg.action === 'closed') {
        text += 'Pull Request ' + msg.action + '\n'
        text += pull_request.title + '\n'
        text += pull_request.body + '\n'
        text += pull_request.html_url
      }
      break
  }

  if (text) {
    const slackWebhookParamName = process.env.SLACK_WEBHOOK_PARAMETER_NAME!
    const slackWebhookUrl = await getParameterValue(slackWebhookParamName)
    const response = await fetch(slackWebhookUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({text})
    })

    if (!response.ok) {
      console.error(
        JSON.stringify({
          error: 'Slack webhook error',
          statusCode: response.status,
          body: await response.text()
        })
      )
      throw new Error('Failed to send request to Slack webhook.')
    }
  }

  return {statusCode: 200, body: '{}'}
}

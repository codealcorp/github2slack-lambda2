import fs from 'node:fs'
import {DecryptCommand, KMSClient} from '@aws-sdk/client-kms'
import yaml from 'js-yaml'
import CryptoJS from 'crypto-js'

const kms = new KMSClient()

async function decryptSecret(cipherBase64Text) {
  const decryptCommand = new DecryptCommand({
    CiphertextBlob: Uint8Array.from(Buffer.from(cipherBase64Text, 'base64'))
  })
  const commandResult = await kms.send(decryptCommand)
  const plaintext = (new TextDecoder()).decode(commandResult.Plaintext)
  return plaintext
}

export async function handle(event) {
  let userMap = yaml.load(fs.readFileSync(`usermap.${process.env['STAGE']}.${process.env['AWS_REGION']}.yml`, 'utf-8'))
  const convertName = (body) => {
    return body.replace(/@([a-zA-Z0-9_\-]+)/g, function (m, m2) {
      if (userMap[m2]) {
        return `<@${userMap[m2]}>`
      } else {
        return m
      }
    })
  }

  const link = function (url, text) {
    return '<' + url + '|' + text + '>';
  };

  const webhookSecret = await decryptSecret(process.env.GITHUB_WEBHOOK_SECRET)

  if (event.headers['X-Hub-Signature'] !== `sha1=${CryptoJS.HmacSHA1(event.body, webhookSecret).toString(CryptoJS.enc.Hex)}`) {
    return {
      statusCode: 401,
      body: 'signature issue',
    }
  }

  const msg = JSON.parse(event.body)
  const eventName = event.headers['X-GitHub-Event']
  let text = ''

  switch (eventName) {
    case 'issue_comment':
    case 'pull_request_review_comment':
      const comment = msg.comment;
      text += comment.user.login + ": \n";
      text += convertName(comment.body) + "\n";
      text += comment.html_url;
      break;
    case 'pull_request_review':
      const review = msg.review;
      text += review.user.login + ": \n";
      text += convertName(review.body) + "\n";
      text += review.html_url;
      break;
    case 'issues':
      const issue = msg.issue;
      if (msg.action === 'opended' || msg.action === 'closed') {
        text += 'Issue ' + msg.action + "\n";
        text += link(issue.html_url, issue.title);
      }
      break;
    case 'push':
      text += 'Pushed' + "\n";
      text += msg.compare + "\n";
      for (let i = 0; i < msg.commits.length; i++) {
        const commit = msg.commits[i];
        text += link(commit.url, commit.id.substr(0, 8)) + ' ' + commit.message + ' - ' + commit.author.name + "\n";
      }
      break;
    case 'pull_request':
      const pull_request = msg.pull_request;
      if (msg.action === 'opended' || msg.action === 'closed') {
        text += 'Pull Request ' + msg.action + "\n";
        text += pull_request.title + "\n";
        text += pull_request.body + "\n";
        text += pull_request.html_url;
      }
      break;
  }

  if (text) {
    const slackWebhookUrl = await decryptSecret(process.env.SLACK_WEBHOOK_URL)
    const response = await fetch(slackWebhookUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({text})
    })

    if (!response.ok) {
      console.error(JSON.stringify({
        error: 'Slack webhook error',
        statusCode: response.status,
        body: await response.text()
      }))
      throw new Error('Failed to send request to Slack webhook.')
    }
  }

  return {statusCode: 200, body: '{}'}
}

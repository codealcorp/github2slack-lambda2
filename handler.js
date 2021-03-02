const fs = require('fs')
const yaml = require('js-yaml')
const {KMS} = require('aws-sdk')
const kms = new KMS()
const CryptoJS = require('crypto-js')
const axios = require('axios')

const handle = async (event) => {
  let userMap = yaml.safeLoad(fs.readFileSync(`usermap.${process.env['STAGE']}.${process.env['AWS_REGION']}.yml`, 'utf-8'))
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

  const githubWebhookSecretData = await kms.decrypt({CiphertextBlob: Buffer(process.env.GITHUB_WEBHOOK_SECRET, 'base64')}).promise()
  const webhookSecret = String(githubWebhookSecretData.Plaintext)

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
    const slackWebhookUrlData = await kms.decrypt({CiphertextBlob: Buffer(process.env.SLACK_WEBHOOK_URL, 'base64')}).promise()
    const slackWebhookUrl = String(slackWebhookUrlData.Plaintext)

    await axios.post(slackWebhookUrl, {text})
  }

  return {statusCode: 200, body: '{}'}
}

module.exports.handle = (event, context, callback) => {
  handle(event).then(r => {
    callback(null, r)
  }).catch(e => {
    console.error(e)
    callback(null, {statusCode: 500, body: JSON.stringify({message: 'Internal server error.'})})
  })
};

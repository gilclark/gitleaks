package gitleaks

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"

	bitbucketv1 "github.com/gfleury/go-bitbucket-v1"
	log "github.com/sirupsen/logrus"
	git "gopkg.in/src-d/go-git.v4"
	"gopkg.in/src-d/go-git.v4/storage/memory"
)

// auditPR audits a single BB PR
// func auditBitbucketPR() ([]Leak, error) {
// 	var leaks []Leak
// 	ctx := context.Background()
// 	bitbucketClient := go-bitbucket.NewClient(githubToken())
// 	splits := strings.Split(opts.GithubPR, "/")
// 	owner := splits[len(splits)-4]
// 	repo := splits[len(splits)-3]
// 	prNum, err := strconv.Atoi(splits[len(splits)-1])
// 	if err != nil {
// 		return nil, err
// 	}

// 	page := 1
// 	for {
// 		commits, resp, err := githubClient.PullRequests.ListCommits(ctx, owner, repo, prNum, &github.ListOptions{
// 			PerPage: githubPages,
// 			Page:    page,
// 		})
// 		if err != nil {
// 			return leaks, err
// 		}

// 		for _, c := range commits {
// 			totalCommits = totalCommits + 1
// 			c, _, err := githubClient.Repositories.GetCommit(ctx, owner, repo, *c.SHA)
// 			if err != nil {
// 				continue
// 			}
// 			files := c.Files
// 			for _, f := range files {
// 				skipFile := false
// 				if f.Patch == nil || f.Filename == nil {
// 					continue
// 				}
// 				for _, re := range config.WhiteList.files {
// 					if re.FindString(f.GetFilename()) != "" {
// 						log.Infof("skipping whitelisted file (matched regex '%s'): %s", re.String(), f.GetFilename())
// 						skipFile = true
// 						break
// 					}
// 				}
// 				if skipFile {
// 					continue
// 				}

// 				commit := &commitInfo{
// 					sha:      c.GetSHA(),
// 					content:  *f.Patch,
// 					filePath: *f.Filename,
// 					repoName: repo,
// 					author:   c.GetCommitter().GetLogin(),
// 					message:  *c.Commit.Message,
// 					date:     *c.Commit.Committer.Date,
// 				}
// 				leaks = append(leaks, inspect(commit)...)
// 			}
// 		}
// 		page = resp.NextPage
// 		if resp.LastPage == 0 {
// 			break
// 		}
// 	}

// 	return leaks, nil
// }

// auditBitbucketRepos kicks off audits if the --bitbucket-project option is set.
// First, we gather all the bitbucket repositories from the bitbucket api (this doesnt actually clone the repos).
// After all the repos have been pulled from bitbucket's api we proceed to audit the repos by calling auditBitbucketRepo.
// If an error occurs during an audit of a repo, that error is logged but won't break the execution cycle.
func auditBitbucketProject() ([]Leak, error) {
	var (
		err             error
		bitbucketRepos  []bitbucketv1.Repository
		resp            *bitbucketv1.APIResponse
		jsonResponse    []byte
		bitbucketClient *bitbucketv1.APIClient
		bitbucketConfig *bitbucketv1.Configuration
		project         bitbucketv1.Project
		leaks           []Leak
		ownerDir        string
	)
	ctx := context.Background()
	bbAuth := bitbucketv1.BasicAuth{
		UserName: config.basicAuth.Username,
		Password: config.basicAuth.Password,
	}
	ctx = context.WithValue(ctx, bitbucketv1.ContextBasicAuth, bbAuth)
	bitbucketConfig = bitbucketv1.NewConfiguration(opts.BitbucketURL + "/rest")
	bitbucketClient = bitbucketv1.NewAPIClient(ctx, bitbucketConfig)

	if resp, err = bitbucketClient.DefaultApi.GetProject(opts.BitbucketProject); err != nil {
		return nil, err
	}
	if jsonResponse, err = json.Marshal(resp.Values); err != nil {
		return nil, err
	}
	if err = json.Unmarshal(jsonResponse, &project); err != nil {
		return nil, err
	}
	log.Infof("project details: %s", string(jsonResponse))

	if resp, err = bitbucketClient.DefaultApi.GetRepositories(opts.BitbucketProject); err != nil {
		return nil, err
	}
	if jsonResponse, err = json.Marshal(resp.Values["values"]); err != nil {
		return nil, err
	}
	if err = json.Unmarshal(jsonResponse, &bitbucketRepos); err != nil {
		return nil, err
	}

	if opts.Disk {
		ownerDir, _ = ioutil.TempDir(dir, opts.GithubUser)
	}
	for _, bitbucketRepo := range bitbucketRepos {
		repoD, err := cloneBitbucketRepo(&project, &bitbucketRepo)
		if err != nil {
			log.Warn(err)
			continue
		}
		leaksFromRepo, err := repoD.audit()
		if opts.Disk {
			os.RemoveAll(fmt.Sprintf("%s/%s", ownerDir, bitbucketRepo.Name))
		}
		if len(leaksFromRepo) == 0 {
			log.Infof("no leaks found for repo %s", bitbucketRepo.Name)
		} else {
			log.Warnf("%d leaks found for repo %s!!!", len(leaksFromRepo), bitbucketRepo.Name)
		}
		if err != nil {
			log.Warn(err)
		}
		leaks = append(leaks, leaksFromRepo...)
	}
	return leaks, nil
}

// cloneBitbucketRepo clones a repo from the url parsed from a github repo. The repo
// will be cloned to disk if --disk is set.
func cloneBitbucketRepo(bitbucketProject *bitbucketv1.Project, bitbucketRepo *bitbucketv1.Repository) (*RepoInfo, error) {
	var (
		repo *git.Repository
		err  error
	)
	for _, re := range config.WhiteList.repos {
		if re.FindString(bitbucketRepo.Name) != "" {
			return nil, fmt.Errorf("skipping %s, whitelisted", bitbucketRepo.Name)
		}
	}
	log.Infof("cloning: %s:%s", bitbucketProject.Name, bitbucketRepo.Name)
	path := fmt.Sprintf("%s/scm/%s/%s.git", opts.BitbucketURL, bitbucketProject.Key, bitbucketRepo.Slug)

	if opts.Disk {
		ownerDir, err := ioutil.TempDir(dir, opts.BitbucketProject)
		if err != nil {
			return nil, fmt.Errorf("unable to generater owner temp dir: %v", err)
		}
		if config.basicAuth != nil {
			repo, err = git.PlainClone(fmt.Sprintf("%s/%s", ownerDir, bitbucketRepo.Name), false, &git.CloneOptions{
				URL:  path,
				Auth: config.basicAuth,
			})
		}
	} else {
		if config.basicAuth != nil {
			repo, err = git.Clone(memory.NewStorage(), nil, &git.CloneOptions{
				URL:  path,
				Auth: config.basicAuth,
			})
		}
	}
	if err != nil {
		return nil, err
	}
	return &RepoInfo{
		repository: repo,
		name:       bitbucketRepo.Name,
	}, nil
}

# repo-template
Generic repo template for Plus3IT repositories

To use this template:

1. Select the green "Use this template" button, or [click here](https://github.com/plus3it/repo-template/generate).
2. Select the repo Owner, give the repo a name, enter a description, select Public or Private, and click "Create repository from template".
3. Clone the repository and create a new branch.
4. Configure the following settings on your new repo.
    * `GENERAL`
        * `Features`
            * Turn off Wikis, Sponsorships, Discussions, and Projects
        * `Pull Requests`
            * Turn off Squash Merging
            * Turn off Rebase Merging
            * Turn on Allow Auto-Merge
            * Turn on Automatically delete head branches
        * `Pushes`
            * Limit how many branches can be updated in a single push: 2
    * `COLLABORATORS and TEAMS`
        * `Manage Access`
            * Add relevant team roles, for example
            * `tardigrade-admins` (Admin)
            * `terraform` (Write)
            * `releasebot` (Write)
    * `Branches`
        * `Create Branch Protection rule` for `main`
            * Turn on Require pull request before merging
            * Turn on Require approvals
            * Turn on Dismiss stale pull requests...
        * `Required Status Checks`
            * As relevant to projects, for example
                * WIP
                * lint/actionlint
                * lint/tardigradelint
                * test / mockstacktest                
            * Turn on Do not allow bypassing the above settings
5. Edit the following files to customize them for the new repository:
    * `LICENSE`
        * Near the end of the file, edit the date and change the repository name
    * `CHANGELOG.template.md`
        * Rename to `CHANGELOG.md`, replacing the repo-template changelog
        * Edit templated items for the new repo
    * `.bumpversion.cfg`
        * Edit the version number for the new repo, ask team if not sure what to
          start with
    * `README.md`
        * Replace contents for the new repo
    * `.github/`
        * Inspect dependabot and workflow files in case changes are needed for
          the new repo
6. Commit the changes and open a pull request

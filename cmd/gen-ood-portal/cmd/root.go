// Copyright 2024 Canonical Ltd.
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package cmd

import (
	"fmt"
	"log"
	"os"

	"github.com/spf13/cobra"

	"github.com/charmed-hpc/ood-portal-generator/internal/config"
)

var logger = log.New(os.Stderr, "gen-ood-portal: ", 0)
const longDesc = `Generate an Open OnDemand portal configuration file.
	
'gen-ood-portal' takes in a yaml configuration file and renders an apache2
configuration file for accessing the Open OnDemand web interface. This command 
should be executed after every update to the yaml configuration file for changes
to the Open Ondemand portal to take effect after restarting the apache2 service.

Examples:

Output rendered portal configuration to stdout:

	gen-ood-portal ./ood_portal.yaml

Output rendered portal configuration to a file:

	gen-ood-portal --output /etc/apache2/conf.d/ood-portal.conf ./ood_portal.yml
`

var rootCmd = &cobra.Command{
	Use:     "gen-ood-portal",
	Short:   "Generate an Open OnDemand portal configuration file.",
	Long:    longDesc,
	Version: "0.1.0",
	Args:    cobra.ExactArgs(1),

	Run: func(cmd *cobra.Command, args []string) {
		configFile := args[0]
		_, err := os.Stat(configFile)
		if err != nil {
			logger.Fatal(err)
		}

		out, err := config.RenderPortal(configFile)
		if err != nil {
			logger.Fatal(err)
		}

		target, _ := cmd.Flags().GetString("output")
		if target != "" {
			err := os.WriteFile(target, []byte(out), 0664)
			if err != nil {
				logger.Fatal(err)
			}
		} else {
			fmt.Println(out)
		}
	},
}

func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		logger.Fatal(err)
	}
}

func init() {
	rootCmd.Flags().StringP("output", "o", "", "output generated portal configuration to file")
}

%{
  configs: [
    %{
      name: "default",
      files: %{
        included: ["lib/", "src/", "test/", "web/", "apps/"],
        excluded: [~r"/_build/", ~r"/deps/"]
      },
      checks: [
        {Credo.Check.Refactor.CyclomaticComplexity, max_complexity: 20},
        {Credo.Check.Refactor.Nesting, max_nesting: 4}
      ]
    }
  ]
}

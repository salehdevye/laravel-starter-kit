<?php

namespace App\Console\Commands;

use App\SallaAuthService;
use Illuminate\Console\Command;
use Illuminate\Support\Str;
use Symfony\Component\Process\Process;

class ServeRemoteCommand extends Command
{
    /**
     * The name and signature of the console command.
     *
     * @var string
     */
    protected $signature = 'serve.remote
                            {--port= : The port to share}';

    /**
     * The console command description.
     *
     * @var string
     */
    protected $description = 'Share the application with ngrok';

    /**
     * Execute the console command.
     *
     * @return int
     */
    public function handle(): int
    {
        $port = $this->option('port') ? : '8000';

        $command = ['ngrok', 'http', '--log', 'stdout'];
        $command[] = $port;


        $webhook_url = route('webhook', [], false);
        $callback_url = route('oauth.callback', [], false);

        $process = new Process($command, null, null, null, null);
        $process->setOptions(['create_new_console' => true]);
        $process->start();
        $process->waitUntil(function ($type, $data) use ($webhook_url, $callback_url, $process) {
//            if (preg_match('/msg="starting web service".*? addr=(?<addr>\S+)/', $data, $matches)) {
//                $this->line('<fg=green>Ngrok Web Interface: </fg=green>'.'http://'.$matches['addr']);
//            }

            if (preg_match('/msg="started tunnel".*? addr=(?<addr>\S+)/', $data, $matches)) {
                $this->line('<fg=green>Local App URL: </fg=green>'.$matches['addr']);
            }

            if (preg_match_all('/msg="started tunnel".*? url=(?<url>\S+)/m', $data, $matches)) {
                $this->line('<fg=green>Remote App URL: </fg=green>'.$matches['url'][1] ?? $matches['url'][0]);

                $this->newLine(1);
                $this->comment('Please go to Salla Partner App -> My Apps -> App Details and update the webhook url to:');
                $webhook_urls = collect($matches['url'])->filter(function ($url) {
                    return Str::startsWith($url, 'https');
                })->map(function ($url) use ($webhook_url) {
                    return $url.$webhook_url;
                })->implode(', ');
                $this->line('<fg=green>Webhook URL: </fg=green>'.$webhook_urls);
                $this->newLine(1);

                if (!app(SallaAuthService::class)->isEasyMode()) {

                    $this->newLine(1);
                    $this->comment('Please go to Salla Partner App -> My Apps -> App Details and update the callback url to:');
                    $callback_urls = collect($matches['url'])->filter(function ($url) {
                        return Str::startsWith($url, 'https');
                    })->map(function ($url) use ($callback_url) {
                        return $url.$callback_url;
                    })->implode(', ');
                    $this->line('<fg=green>OAuth Callback URL: </fg=green>'.$callback_urls);
                    $this->newLine(1);
                }
            }


            if ($process::OUT === $type) {
                $this->line($data, null, 'vv');
            } else {
                $this->warn("error :- ".$data);
            }

            return Str::contains($data,'started tunnel');
        });

        $this->call('serve', [
            '--port' => $port
        ]);

        return 0;
    }
}

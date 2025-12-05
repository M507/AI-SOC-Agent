// PDF Export functionality for autoruns
// Exports autorun chat history as PDF

class PDFExporter {
    /**
     * Export autorun chat as PDF.
     * @param {Object} autorun - The autorun object to export
     * @param {Object} controller - The AIController instance (for API access and debug mode)
     * @param {HTMLElement} terminal - Optional terminal element for fallback content
     */
    async exportAutorun(autorun, controller, terminal = null) {
        console.log('[PDFExporter] ===== PDF Export Started =====');
        console.log('[PDFExporter] Step 1: Validating autorun:', autorun?.id);
        
        if (!autorun) {
            console.error('[PDFExporter] ERROR: exportAutorun called with null/undefined autorun');
            return;
        }

        console.log('[PDFExporter] ✓ Autorun validated:', {
            id: autorun.id,
            name: autorun.name,
            session_id: autorun.session_id,
            enabled: autorun.enabled
        });

        console.log('[PDFExporter] Step 2: Checking html2pdf library...');
        // Check if html2pdf is available
        if (typeof html2pdf === 'undefined') {
            console.error('[PDFExporter] ERROR: html2pdf library not loaded');
            alert('PDF export library not loaded. Please refresh the page and try again.');
            return;
        }
        console.log('[PDFExporter] ✓ html2pdf library is available');

        try {
            console.log('[PDFExporter] Step 3: Fetching session data from API...');
            // Get session data directly from API to ensure we have all content
            let sessionData = null;
            if (autorun.session_id && controller && controller.api) {
                console.log('[PDFExporter] Attempting to fetch session:', autorun.session_id);
                try {
                    const sessionResponse = await controller.api.getSession(autorun.session_id);
                    console.log('[PDFExporter] Session API response:', {
                        success: sessionResponse?.success,
                        hasSession: !!sessionResponse?.session,
                        entryCount: sessionResponse?.session?.entries?.length || 0
                    });
                    if (sessionResponse && sessionResponse.success && sessionResponse.session) {
                        sessionData = sessionResponse.session;
                        console.log('[PDFExporter] ✓ Session data loaded:', {
                            id: sessionData.id,
                            name: sessionData.name,
                            entryCount: sessionData.entries?.length || 0
                        });
                    } else {
                        console.warn('[PDFExporter] Session response missing data:', sessionResponse);
                    }
                } catch (error) {
                    console.warn('[PDFExporter] Could not fetch session data, using terminal content:', error);
                    console.warn('[PDFExporter] Error details:', {
                        message: error.message,
                        stack: error.stack
                    });
                }
            } else {
                console.log('[PDFExporter] Skipping API fetch - missing:', {
                    hasSessionId: !!autorun.session_id,
                    hasController: !!controller,
                    hasApi: !!(controller && controller.api)
                });
            }

            console.log('[PDFExporter] Step 4: Getting terminal element...');
            // Get terminal content as fallback
            if (!terminal) {
                terminal = document.getElementById('autorun-terminal');
            }
            if (!terminal) {
                console.error('[PDFExporter] ERROR: Terminal element not found in DOM');
                alert('Terminal content not found.');
                return;
            }
            console.log('[PDFExporter] ✓ Terminal element found:', {
                exists: !!terminal,
                childrenCount: terminal.children.length,
                textLength: terminal.textContent.trim().length,
                innerHTMLLength: terminal.innerHTML.length
            });

            // Check if we have any content
            const hasTerminalContent = terminal.children.length > 0 || terminal.textContent.trim().length > 0;
            const hasSessionData = sessionData && sessionData.entries && sessionData.entries.length > 0;

            console.log('[PDFExporter] Step 5: Validating content availability...');
            console.log('[PDFExporter] Content check results:', {
                hasTerminalContent,
                hasSessionData,
                terminalChildren: terminal.children.length,
                terminalTextLength: terminal.textContent.trim().length,
                sessionEntryCount: sessionData?.entries?.length || 0
            });

            if (!hasTerminalContent && !hasSessionData) {
                console.error('[PDFExporter] ERROR: No content available to export');
                alert('No content to export. The autorun chat is empty.');
                return;
            }
            console.log('[PDFExporter] ✓ Content validation passed');

            console.log('[PDFExporter] Step 6: Building chat content...');
            // Build chat content from session data if available, otherwise use terminal
            let chatContent = '';
            
            if (hasSessionData) {
                console.log('[PDFExporter] Building content from session entries...');
                let entryCount = 0;
                sessionData.entries.forEach((entry, index) => {
                    entryCount++;
                    const timestamp = new Date(entry.timestamp);
                    // Improved styling with consistent spacing
                    chatContent += `<div style="margin: 0; padding: 0; border-bottom: 1px solid #ecf0f1; page-break-inside: avoid;">`;
                    chatContent += `<div style="padding: 15px 20px; background: #ffffff;">`;
                    
                    // Timestamp
                    chatContent += `<div style="color: #7f8c8d; font-size: 9pt; margin-bottom: 8px; font-weight: 500; letter-spacing: 0.5px;">[${timestamp.toLocaleString()}]</div>`;
                    
                    // Command
                    chatContent += `<div style="color: #2980b9; font-weight: 600; margin-bottom: 10px; font-family: 'Courier New', monospace; font-size: 10.5pt; padding: 8px 12px; background: #ebf5fb; border-left: 4px solid #3498db; border-radius: 3px;">> ${escapeHtml(entry.command || 'N/A')}</div>`;
                    
                    // Result
                    if (entry.result) {
                        const isError = entry.status === 'failed' || entry.status === 'stopped';
                        const text = controller && controller.uiDebugMode
                            ? formatDebugResult(entry.result)
                            : extractResultText(entry.result);
                        
                        const resultText = text || (isError ? 'Error (no details returned)' : 'Command completed');
                        const textColor = isError ? '#c0392b' : '#2c3e50';
                        const bgColor = isError ? '#fdf2f2' : '#f8f9fa';
                        const borderColor = isError ? '#e74c3c' : '#bdc3c7';
                        
                        chatContent += `<div style="color: ${textColor}; font-family: 'Courier New', monospace; white-space: pre-wrap; word-wrap: break-word; background: ${bgColor}; padding: 12px 15px; border-left: 4px solid ${borderColor}; border-radius: 3px; margin-top: 8px; font-size: 10pt; line-height: 1.6;">${escapeHtml(resultText)}</div>`;
                    } else if (entry.status === 'pending' || entry.status === 'running') {
                        chatContent += `<div style="color: #f39c12; font-style: italic; padding: 8px 12px; background: #fef9e7; border-left: 4px solid #f1c40f; border-radius: 3px; margin-top: 8px;">⏳ Executing...</div>`;
                    }
                    
                    chatContent += `</div></div>`;
                    
                    if (index < 3) {
                        console.log(`[PDFExporter] Processed entry ${index + 1}:`, {
                            command: entry.command?.substring(0, 50),
                            hasResult: !!entry.result,
                            status: entry.status
                        });
                    }
                });
                console.log(`[PDFExporter] ✓ Built content from ${entryCount} session entries`);
                console.log('[PDFExporter] Chat content length:', chatContent.length);
            } else {
                console.log('[PDFExporter] Building content from terminal DOM...');
                // Fallback: use terminal content
                const terminalClone = terminal.cloneNode(true);
                
                // Convert terminal styles to inline styles for PDF with improved spacing
                this.styleTerminalForPDF(terminalClone);
                chatContent = terminalClone.innerHTML;
                console.log('[PDFExporter] ✓ Built content from terminal DOM');
                console.log('[PDFExporter] Terminal clone content length:', chatContent.length);
            }
            
            console.log('[PDFExporter] Step 7: Creating PDF container element...');
            // Create a temporary container for PDF generation
            const pdfContainer = this.createPDFContainer();
            console.log('[PDFExporter] ✓ PDF container created with styles (off-screen)');

            // Build the PDF content with improved styling
            const htmlContent = this.buildPDFContent(autorun, chatContent);
            console.log('[PDFExporter] Step 8: Setting container HTML content...');
            console.log('[PDFExporter] HTML content length:', htmlContent.length);
            pdfContainer.innerHTML = htmlContent;
            console.log('[PDFExporter] ✓ HTML content set');
            
            console.log('[PDFExporter] Step 9: Appending container to DOM...');
            document.body.appendChild(pdfContainer);
            console.log('[PDFExporter] ✓ Container appended to body');

            console.log('[PDFExporter] Step 10: Waiting for content to render...');
            // Wait for content to render and force layout calculation
            await new Promise(resolve => setTimeout(resolve, 300));
            
            // Force browser to calculate layout
            const height = pdfContainer.offsetHeight;
            const width = pdfContainer.offsetWidth;
            console.log('[PDFExporter] Container dimensions after render:', { width, height });
            
            // Additional wait to ensure all content is rendered
            await new Promise(resolve => setTimeout(resolve, 200));
            console.log('[PDFExporter] ✓ Render wait completed');

            // Debug: Log content info
            console.log('[PDFExporter] Step 11: Validating container content...');
            console.log('[PDFExporter] PDF Export Debug:', {
                containerExists: !!pdfContainer,
                containerInDOM: pdfContainer.parentNode === document.body,
                hasInnerHTML: pdfContainer.innerHTML.length > 0,
                innerHTMLLength: pdfContainer.innerHTML.length,
                hasTextContent: pdfContainer.textContent.trim().length > 0,
                textContentLength: pdfContainer.textContent.trim().length,
                chatContentLength: chatContent.length,
                sessionEntries: sessionData ? sessionData.entries?.length : 0,
                terminalChildren: terminal ? terminal.children.length : 0,
                containerOffsetWidth: pdfContainer.offsetWidth,
                containerOffsetHeight: pdfContainer.offsetHeight,
                containerScrollWidth: pdfContainer.scrollWidth,
                containerScrollHeight: pdfContainer.scrollHeight
            });

            // Verify content exists
            if (!pdfContainer.innerHTML || pdfContainer.innerHTML.trim().length < 100) {
                console.error('[PDFExporter] ERROR: PDF container has insufficient content');
                console.error('[PDFExporter] InnerHTML length:', pdfContainer.innerHTML.length);
                console.error('[PDFExporter] InnerHTML preview:', pdfContainer.innerHTML.substring(0, 500));
                if (pdfContainer.parentNode) {
                    document.body.removeChild(pdfContainer);
                }
                alert('Error: No content to export. Please check the console for details.');
                return;
            }
            console.log('[PDFExporter] ✓ Content validation passed');

            // Log the actual content for debugging
            console.log('[PDFExporter] Step 12: Content preview...');
            console.log('[PDFExporter] PDF container text content preview (first 500 chars):', pdfContainer.textContent.substring(0, 500));
            console.log('[PDFExporter] PDF container HTML preview (first 1000 chars):', pdfContainer.innerHTML.substring(0, 1000));

            console.log('[PDFExporter] Step 13: Configuring PDF options...');
            const filename = `${(autorun.name || 'autorun').replace(/[^a-z0-9]/gi, '_')}_${new Date().toISOString().split('T')[0]}.pdf`;
            console.log('[PDFExporter] PDF filename:', filename);
            
            // Configure PDF options
            const containerWidth = pdfContainer.offsetWidth || pdfContainer.scrollWidth || 794;
            const containerHeight = pdfContainer.offsetHeight || pdfContainer.scrollHeight || 1123;
            
            console.log('[PDFExporter] Final container dimensions:', {
                offsetWidth: pdfContainer.offsetWidth,
                offsetHeight: pdfContainer.offsetHeight,
                scrollWidth: pdfContainer.scrollWidth,
                scrollHeight: pdfContainer.scrollHeight,
                clientWidth: pdfContainer.clientWidth,
                clientHeight: pdfContainer.clientHeight,
                usedWidth: containerWidth,
                usedHeight: containerHeight
            });
            
            const opt = this.createPDFOptions(filename, containerWidth, containerHeight);
            console.log('[PDFExporter] ✓ PDF options configured:', {
                filename: opt.filename,
                html2canvas: {
                    scale: opt.html2canvas.scale,
                    width: opt.html2canvas.width,
                    height: opt.html2canvas.height
                }
            });

            try {
                // Generate and download PDF
                console.log('[PDFExporter] Step 14: Starting PDF generation...');
                console.log('[PDFExporter] Container dimensions:', {
                    offsetWidth: pdfContainer.offsetWidth,
                    offsetHeight: pdfContainer.offsetHeight,
                    scrollWidth: pdfContainer.scrollWidth,
                    scrollHeight: pdfContainer.scrollHeight,
                    clientWidth: pdfContainer.clientWidth,
                    clientHeight: pdfContainer.clientHeight
                });
                
                // Temporarily move container to viewport for html2canvas to capture it
                // Store original position
                const originalLeft = pdfContainer.style.left;
                const originalTop = pdfContainer.style.top;
                const originalZIndex = pdfContainer.style.zIndex;
                
                // Move to viewport (but keep it visually hidden by making it very small/transparent)
                pdfContainer.style.position = 'fixed';
                pdfContainer.style.top = '0';
                pdfContainer.style.left = '0';
                pdfContainer.style.zIndex = '999999';
                pdfContainer.style.width = containerWidth + 'px';
                pdfContainer.style.height = 'auto';
                pdfContainer.style.maxHeight = 'none';
                
                // Force a reflow to ensure content is rendered
                await new Promise(resolve => setTimeout(resolve, 100));
                const forcedHeight = pdfContainer.offsetHeight;
                console.log('[PDFExporter] Forced reflow, height:', forcedHeight);
                
                console.log('[PDFExporter] Calling html2pdf().set().from().save()...');
                await html2pdf().set(opt).from(pdfContainer).save();
                console.log('[PDFExporter] ✓ PDF generation completed successfully');
                
                // Restore original position
                pdfContainer.style.left = originalLeft;
                pdfContainer.style.top = originalTop;
                pdfContainer.style.zIndex = originalZIndex;
            } catch (pdfError) {
                console.error('[PDFExporter] ERROR: PDF generation failed');
                console.error('[PDFExporter] Error type:', pdfError.constructor.name);
                console.error('[PDFExporter] Error message:', pdfError.message);
                console.error('[PDFExporter] Error stack:', pdfError.stack);
                console.error('[PDFExporter] Full error object:', pdfError);
                
                // Fallback: Try with simpler options
                try {
                    console.log('[PDFExporter] Step 15: Attempting fallback PDF generation...');
                    const fallbackOpt = this.createFallbackPDFOptions(filename);
                    console.log('[PDFExporter] Fallback options:', fallbackOpt);
                    await html2pdf().set(fallbackOpt).from(pdfContainer).save();
                    console.log('[PDFExporter] ✓ Fallback PDF generation succeeded');
                } catch (fallbackError) {
                    console.error('[PDFExporter] ERROR: Fallback PDF generation also failed');
                    console.error('[PDFExporter] Fallback error type:', fallbackError.constructor.name);
                    console.error('[PDFExporter] Fallback error message:', fallbackError.message);
                    console.error('[PDFExporter] Fallback error stack:', fallbackError.stack);
                    console.error('[PDFExporter] Full fallback error object:', fallbackError);
                    alert('Error generating PDF. Please check the browser console for details. The content may be too large or there may be a rendering issue.');
                    throw fallbackError;
                }
            } finally {
                console.log('[PDFExporter] Step 16: Cleaning up container...');
                // Clean up - remove container
                if (pdfContainer.parentNode) {
                    document.body.removeChild(pdfContainer);
                    console.log('[PDFExporter] ✓ Container removed from DOM');
                } else {
                    console.warn('[PDFExporter] Container was already removed from DOM');
                }
            }

            console.log(`[PDFExporter] ===== PDF Export Completed Successfully =====`);
            console.log(`[PDFExporter] Autorun ID: ${autorun.id}`);
        } catch (error) {
            console.error('[PDFExporter] ===== PDF Export Failed =====');
            console.error('[PDFExporter] Error type:', error.constructor.name);
            console.error('[PDFExporter] Error message:', error.message);
            console.error('[PDFExporter] Error stack:', error.stack);
            console.error('[PDFExporter] Full error object:', error);
            alert('Error exporting autorun to PDF. See console for details.');
        }
    }

    /**
     * Create PDF container element with proper styling.
     */
    createPDFContainer() {
        const pdfContainer = document.createElement('div');
        pdfContainer.id = 'pdf-export-container';
        // Position off-screen but visible to html2canvas (not using visibility: hidden or opacity: 0)
        pdfContainer.style.position = 'absolute';
        pdfContainer.style.top = '0';
        pdfContainer.style.left = '-10000px'; // Off-screen but still in document flow
        pdfContainer.style.width = '794px'; // A4 width in pixels (210mm at 96 DPI)
        pdfContainer.style.minHeight = '1123px'; // A4 height in pixels
        pdfContainer.style.padding = '40px';
        pdfContainer.style.fontFamily = 'Arial, sans-serif';
        pdfContainer.style.fontSize = '11pt';
        pdfContainer.style.lineHeight = '1.5';
        pdfContainer.style.color = '#333';
        pdfContainer.style.backgroundColor = '#ffffff';
        pdfContainer.style.boxSizing = 'border-box';
        pdfContainer.style.overflow = 'visible';
        pdfContainer.style.zIndex = '-1'; // Behind everything
        return pdfContainer;
    }

    /**
     * Build PDF HTML content.
     */
    buildPDFContent(autorun, chatContent) {
        return `
            <div style="margin-bottom: 30px; padding-bottom: 20px; border-bottom: 3px solid #2c3e50;">
                <h1 style="margin: 0 0 15px 0; font-size: 28pt; color: #2c3e50; font-weight: 600; letter-spacing: -0.5px;">${escapeHtml(autorun.name || 'Autorun')}</h1>
                <div style="font-size: 10pt; color: #555; line-height: 1.8; background: #f8f9fa; padding: 15px; border-radius: 6px; border-left: 4px solid #3498db;">
                    <p style="margin: 8px 0;"><strong style="color: #2c3e50; min-width: 140px; display: inline-block;">Status:</strong> <span style="color: ${autorun.enabled ? '#27ae60' : '#e74c3c'}; font-weight: 600;">${autorun.enabled ? 'Enabled' : 'Disabled'}</span></p>
                    <p style="margin: 8px 0;"><strong style="color: #2c3e50; min-width: 140px; display: inline-block;">Starting Prompt:</strong> <span style="color: #34495e; font-family: 'Courier New', monospace; font-size: 9.5pt;">${escapeHtml(autorun.command || 'N/A')}</span></p>
                    ${autorun.condition_function ? `<p style="margin: 8px 0;"><strong style="color: #2c3e50; min-width: 140px; display: inline-block;">Condition Function:</strong> <span style="color: #34495e; font-family: 'Courier New', monospace;">${escapeHtml(autorun.condition_function)}</span></p>` : ''}
                    <p style="margin: 8px 0;"><strong style="color: #2c3e50; min-width: 140px; display: inline-block;">Interval:</strong> <span style="color: #34495e;">${autorun.interval_seconds}s (${formatInterval(autorun.interval_seconds)})</span></p>
                    ${autorun.last_run ? `<p style="margin: 8px 0;"><strong style="color: #2c3e50; min-width: 140px; display: inline-block;">Last Run:</strong> <span style="color: #34495e;">${new Date(autorun.last_run).toLocaleString()}</span></p>` : ''}
                    ${autorun.next_run ? `<p style="margin: 8px 0;"><strong style="color: #2c3e50; min-width: 140px; display: inline-block;">Next Run:</strong> <span style="color: #34495e;">${new Date(autorun.next_run).toLocaleString()}</span></p>` : ''}
                    <p style="margin: 8px 0;"><strong style="color: #2c3e50; min-width: 140px; display: inline-block;">Export Date:</strong> <span style="color: #34495e;">${new Date().toLocaleString()}</span></p>
                </div>
            </div>
            <div style="margin-top: 30px;">
                <h2 style="font-size: 20pt; margin-bottom: 20px; padding-bottom: 10px; border-bottom: 2px solid #ecf0f1; color: #2c3e50; font-weight: 600;">Chat History</h2>
                <div style="background-color: #ffffff; border: 1px solid #e0e0e0; border-radius: 6px; padding: 0; margin-top: 15px;">
                    ${chatContent || '<div style="color: #95a5a6; font-style: italic; padding: 20px; text-align: center;">No chat history available.</div>'}
                </div>
            </div>
        `;
    }

    /**
     * Create PDF options for html2pdf.
     */
    createPDFOptions(filename, width, height) {
        return {
            margin: [10, 10, 10, 10],
            filename: filename,
            image: { type: 'jpeg', quality: 0.98 },
            html2canvas: { 
                scale: 2,
                useCORS: true,
                logging: true, // Enable logging for debugging
                backgroundColor: '#ffffff',
                width: width,
                height: height,
                windowWidth: width,
                windowHeight: height,
                x: 0,
                y: 0,
                scrollX: 0,
                scrollY: 0,
                allowTaint: false,
                removeContainer: false,
                onclone: (clonedDoc, element) => {
                    // Ensure the cloned container is visible and positioned correctly
                    const clonedContainer = clonedDoc.getElementById('pdf-export-container');
                    if (clonedContainer) {
                        clonedContainer.style.position = 'absolute';
                        clonedContainer.style.top = '0';
                        clonedContainer.style.left = '0';
                        clonedContainer.style.visibility = 'visible';
                        clonedContainer.style.opacity = '1';
                        clonedContainer.style.zIndex = '1';
                        clonedContainer.style.width = width + 'px';
                        clonedContainer.style.height = 'auto';
                        clonedContainer.style.maxHeight = 'none';
                        console.log('[PDFExporter] Cloned container made visible for capture:', {
                            width: clonedContainer.offsetWidth,
                            height: clonedContainer.offsetHeight,
                            scrollHeight: clonedContainer.scrollHeight
                        });
                    } else {
                        console.warn('[PDFExporter] Cloned container not found in cloned document');
                    }
                }
            },
            jsPDF: { 
                unit: 'mm', 
                format: 'a4', 
                orientation: 'portrait' 
            },
            pagebreak: { mode: ['avoid-all', 'css', 'legacy'] }
        };
    }

    /**
     * Create fallback PDF options with simpler settings.
     */
    createFallbackPDFOptions(filename) {
        return {
            margin: [10, 10, 10, 10],
            filename: filename,
            image: { type: 'jpeg', quality: 0.95 },
            html2canvas: { 
                scale: 1.5,
                useCORS: true,
                logging: true,
                backgroundColor: '#ffffff'
            },
            jsPDF: { 
                unit: 'mm', 
                format: 'a4', 
                orientation: 'portrait' 
            }
        };
    }

    /**
     * Convert terminal styles to inline styles for PDF with improved spacing.
     */
    styleTerminalForPDF(element) {
        const elements = element.querySelectorAll('*');
        let lastWasOutput = false;
        
        elements.forEach((el, idx) => {
            if (el.classList.contains('terminal-line')) {
                // Reset spacing for new blocks (timestamp indicates new block)
                if (el.classList.contains('timestamp')) {
                    if (lastWasOutput) {
                        // Add spacing before new block
                        el.style.marginTop = '20px';
                    }
                    el.style.marginBottom = '8px';
                    el.style.marginTop = lastWasOutput ? '20px' : '0';
                    lastWasOutput = false;
                } else {
                    el.style.margin = '0';
                    el.style.marginBottom = '0';
                }
                
                el.style.padding = '0';
                el.style.fontFamily = "'Courier New', monospace";
                el.style.fontSize = '10pt';
                el.style.lineHeight = '1.5';
                el.style.whiteSpace = 'pre-wrap';
                el.style.wordWrap = 'break-word';
            }
            
            if (el.classList.contains('command')) {
                el.style.color = '#2980b9';
                el.style.fontWeight = '600';
                el.style.padding = '8px 12px';
                el.style.background = '#ebf5fb';
                el.style.borderLeft = '4px solid #3498db';
                el.style.borderRadius = '3px';
                el.style.marginBottom = '10px';
                el.style.marginTop = '0';
            }
            if (el.classList.contains('output')) {
                el.style.color = '#2c3e50';
                el.style.background = '#f8f9fa';
                el.style.padding = '12px 15px';
                el.style.borderLeft = '4px solid #bdc3c7';
                el.style.borderRadius = '3px';
                el.style.marginTop = '8px';
                el.style.marginBottom = '20px';
                el.style.paddingBottom = '15px';
                el.style.borderBottom = '1px solid #ecf0f1';
                lastWasOutput = true;
            }
            if (el.classList.contains('error')) {
                el.style.color = '#c0392b';
                el.style.background = '#fdf2f2';
                el.style.padding = '12px 15px';
                el.style.borderLeft = '4px solid #e74c3c';
                el.style.borderRadius = '3px';
                el.style.marginTop = '8px';
                el.style.marginBottom = '20px';
                el.style.paddingBottom = '15px';
                el.style.borderBottom = '1px solid #ecf0f1';
                lastWasOutput = true;
            }
            if (el.classList.contains('timestamp')) {
                el.style.color = '#7f8c8d';
                el.style.fontSize = '9pt';
                el.style.fontWeight = '500';
                el.style.letterSpacing = '0.5px';
            }
            
            // Remove class to avoid conflicts
            if (el.classList.contains('terminal-line')) {
                el.removeAttribute('class');
            }
        });
    }
}

// Create a singleton instance
const pdfExporter = new PDFExporter();

